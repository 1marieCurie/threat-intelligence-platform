from __future__ import annotations

from collections import defaultdict
from collections.abc import (
    Iterable,
    Iterator,
    Sequence,
)
from typing import (
    Any,
    TypeVar,
)
from uuid import (
    UUID,
    uuid4,
)

from sqlalchemy import (
    String,
    and_,
    case,
    cast,
    func,
    or_,
    select,
    tuple_,
)
from sqlalchemy.dialects.postgresql import (
    insert,
)
from sqlalchemy.exc import (
    IntegrityError,
    SQLAlchemyError,
)
from sqlalchemy.orm import Session

from application.models.canonical_url_identity import (
    CanonicalURLIdentity,
)
from application.ports.outbound.canonical_web_indicator_repository import (
    CanonicalWebIndicatorConflictError,
    CanonicalWebIndicatorRepositoryError,
    WebIndicatorIdentityKey,
    WebIndicatorObservationKey,
)
from domain.canonical_web_indicator import (
    CanonicalWebIndicator,
)
from domain.web_indicator_observation import (
    WebIndicatorObservation,
)
from infrastructure.persistence.models.canonical_web import (
    CanonicalWebIndicatorModel,
    CanonicalWebIndicatorObservationModel,
)


_T = TypeVar(
    "_T"
)


class SqlAlchemyCanonicalWebIndicatorRepository:
    """
    Repository PostgreSQL des indicateurs Web canoniques.

    Garanties :

    - lectures groupées et bornées ;
    - identité exacte par version et SHA-256 ;
    - propriété d'une observation source immuable ;
    - conservation monotone des observations existantes ;
    - aucune suppression SQL ;
    - aucune URL exposée dans les erreurs.
    """

    LOOKUP_BATCH_SIZE = 1_000
    WRITE_BATCH_SIZE = 500
    MAX_UPSERT_AGGREGATES = 5_000

    def __init__(
        self,
        *,
        session: Session,
    ) -> None:
        if session is None:
            raise ValueError(
                "session must not be None"
            )

        self._session = session

    def find_by_id(
        self,
        indicator_id: UUID,
    ) -> CanonicalWebIndicator | None:
        normalized_id = self._normalize_uuid(
            indicator_id,
            field_name="indicator_id",
        )

        aggregates = self.find_many_by_ids(
            (
                normalized_id,
            )
        )

        return aggregates.get(
            normalized_id
        )

    def find_many_by_ids(
        self,
        indicator_ids: Iterable[UUID],
    ) -> dict[
        UUID,
        CanonicalWebIndicator,
    ]:
        normalized_ids = (
            self._normalize_uuid_iterable(
                indicator_ids,
                field_name="indicator_ids",
            )
        )

        if not normalized_ids:
            return {}

        try:
            return self._load_aggregates(
                normalized_ids
            )

        except SQLAlchemyError as error:
            raise (
                CanonicalWebIndicatorRepositoryError(
                    "Unable to read canonical "
                    "Web indicators"
                )
            ) from error

    def find_many_by_identities(
        self,
        identities: Iterable[
            CanonicalURLIdentity
        ],
    ) -> dict[
        WebIndicatorIdentityKey,
        CanonicalWebIndicator,
    ]:
        requested_keys = (
            self._normalize_identity_keys(
                identities
            )
        )

        if not requested_keys:
            return {}

        try:
            owners_by_key = (
                self._find_identity_owners(
                    requested_keys,
                    for_update=False,
                )
            )

            aggregate_ids = tuple(
                dict.fromkeys(
                    owners_by_key.values()
                )
            )

            aggregates_by_id = (
                self._load_aggregates(
                    aggregate_ids
                )
            )

        except SQLAlchemyError as error:
            raise (
                CanonicalWebIndicatorRepositoryError(
                    "Unable to resolve canonical "
                    "Web identities"
                )
            ) from error

        return {
            key: aggregates_by_id[
                owners_by_key[key]
            ]
            for key in requested_keys
            if (
                key in owners_by_key
                and owners_by_key[key]
                in aggregates_by_id
            )
        }

    def find_many_by_observations(
        self,
        observations: Iterable[
            WebIndicatorObservation
        ],
    ) -> dict[
        WebIndicatorObservationKey,
        CanonicalWebIndicator,
    ]:
        requested_keys = (
            self._normalize_observation_keys(
                observations
            )
        )

        if not requested_keys:
            return {}

        try:
            owners_by_key = (
                self._find_observation_owners(
                    requested_keys,
                    for_update=False,
                )
            )

            aggregate_ids = tuple(
                dict.fromkeys(
                    owners_by_key.values()
                )
            )

            aggregates_by_id = (
                self._load_aggregates(
                    aggregate_ids
                )
            )

        except SQLAlchemyError as error:
            raise (
                CanonicalWebIndicatorRepositoryError(
                    "Unable to resolve canonical "
                    "Web observations"
                )
            ) from error

        return {
            key: aggregates_by_id[
                owners_by_key[key]
            ]
            for key in requested_keys
            if (
                key in owners_by_key
                and owners_by_key[key]
                in aggregates_by_id
            )
        }

    def upsert_many(
        self,
        indicators: Iterable[
            CanonicalWebIndicator
        ],
    ) -> int:
        normalized_indicators = (
            self._normalize_indicators(
                indicators
            )
        )

        if not normalized_indicators:
            return 0

        if (
            len(normalized_indicators)
            > self.MAX_UPSERT_AGGREGATES
        ):
            raise ValueError(
                "indicators exceeds the configured "
                f"limit of "
                f"{self.MAX_UPSERT_AGGREGATES}"
            )

        parent_rows = [
            self._parent_row(
                indicator
            )
            for indicator
            in normalized_indicators
        ]

        observation_rows = [
            self._observation_row(
                indicator_id=indicator.id,
                observation=observation,
            )
            for indicator
            in normalized_indicators
            for observation
            in indicator.observations
        ]

        requested_identity_owners = {
            self._identity_key_from_aggregate(
                indicator
            ): indicator.id
            for indicator
            in normalized_indicators
        }

        requested_observation_owners = {
            observation.key: indicator.id
            for indicator
            in normalized_indicators
            for observation
            in indicator.observations
        }

        try:
            self._lock_and_validate_parents(
                normalized_indicators
            )

            existing_identity_owners = (
                self._find_identity_owners(
                    tuple(
                        requested_identity_owners
                    ),
                    for_update=True,
                )
            )

            self._validate_identity_ownership(
                existing_owners=(
                    existing_identity_owners
                ),
                requested_owners=(
                    requested_identity_owners
                ),
            )

            existing_observation_owners = (
                self._find_observation_owners(
                    tuple(
                        requested_observation_owners
                    ),
                    for_update=True,
                )
            )

            self._validate_observation_ownership(
                existing_owners=(
                    existing_observation_owners
                ),
                requested_owners=(
                    requested_observation_owners
                ),
            )

            self._upsert_parent_rows(
                parent_rows
            )

            self._upsert_observation_rows(
                observation_rows
            )

            self._session.flush()

        except CanonicalWebIndicatorConflictError:
            raise

        except IntegrityError as error:
            raise (
                CanonicalWebIndicatorConflictError(
                    "Canonical Web indicator "
                    "persistence conflict"
                )
            ) from error

        except SQLAlchemyError as error:
            raise (
                CanonicalWebIndicatorRepositoryError(
                    "Unable to persist canonical "
                    "Web indicators"
                )
            ) from error

        return len(
            normalized_indicators
        )

    def _load_aggregates(
        self,
        indicator_ids: Sequence[UUID],
    ) -> dict[
        UUID,
        CanonicalWebIndicator,
    ]:
        if not indicator_ids:
            return {}

        parent_models_by_id: dict[
            UUID,
            CanonicalWebIndicatorModel,
        ] = {}

        for batch in self._chunked(
            indicator_ids,
            self.LOOKUP_BATCH_SIZE,
        ):
            statement = (
                select(
                    CanonicalWebIndicatorModel
                )
                .where(
                    CanonicalWebIndicatorModel
                    .id
                    .in_(batch)
                )
                .execution_options(
                    populate_existing=True
                )
            )

            models = (
                self._session
                .execute(statement)
                .scalars()
                .all()
            )

            for model in models:
                parent_models_by_id[
                    model.id
                ] = model

        found_ids = tuple(
            indicator_id
            for indicator_id in indicator_ids
            if indicator_id
            in parent_models_by_id
        )

        if not found_ids:
            return {}

        observations_by_id: defaultdict[
            UUID,
            list[
                CanonicalWebIndicatorObservationModel
            ],
        ] = defaultdict(list)

        for batch in self._chunked(
            found_ids,
            self.LOOKUP_BATCH_SIZE,
        ):
            statement = (
                select(
                    CanonicalWebIndicatorObservationModel
                )
                .where(
                    CanonicalWebIndicatorObservationModel
                    .indicator_id
                    .in_(batch)
                )
                .order_by(
                    CanonicalWebIndicatorObservationModel
                    .indicator_id,
                    CanonicalWebIndicatorObservationModel
                    .observed_at,
                    CanonicalWebIndicatorObservationModel
                    .source,
                    CanonicalWebIndicatorObservationModel
                    .source_record_key,
                )
                .execution_options(
                    populate_existing=True
                )
            )

            models = (
                self._session
                .execute(statement)
                .scalars()
                .all()
            )

            for model in models:
                observations_by_id[
                    model.indicator_id
                ].append(
                    model
                )

        aggregates: dict[
            UUID,
            CanonicalWebIndicator,
        ] = {}

        for indicator_id in found_ids:
            parent = parent_models_by_id[
                indicator_id
            ]

            try:
                aggregate = CanonicalWebIndicator(
                    id=parent.id,
                    indicator_type=(
                        parent.indicator_type
                    ),
                    canonical_value=(
                        parent.canonical_value
                    ),
                    value_hash=parent.value_hash,
                    hostname=parent.hostname,
                    canonicalization_version=(
                        parent
                        .canonicalization_version
                    ),
                    observations=tuple(
                        self._to_observation(
                            model
                        )
                        for model
                        in observations_by_id[
                            indicator_id
                        ]
                    ),
                    created_at=parent.created_at,
                    updated_at=parent.updated_at,
                )

            except (
                TypeError,
                ValueError,
            ) as error:
                raise (
                    CanonicalWebIndicatorRepositoryError(
                        "Persisted canonical Web "
                        "aggregate is invalid"
                    )
                ) from error

            aggregates[
                indicator_id
            ] = aggregate

        return aggregates

    def _lock_and_validate_parents(
        self,
        indicators: Sequence[
            CanonicalWebIndicator
        ],
    ) -> None:
        indicators_by_id = {
            indicator.id: indicator
            for indicator in indicators
        }

        ordered_ids = sorted(
            indicators_by_id,
            key=str,
        )

        for batch in self._chunked(
            ordered_ids,
            self.LOOKUP_BATCH_SIZE,
        ):
            statement = (
                select(
                    CanonicalWebIndicatorModel
                )
                .where(
                    CanonicalWebIndicatorModel
                    .id
                    .in_(batch)
                )
                .order_by(
                    CanonicalWebIndicatorModel.id
                )
                .with_for_update()
            )

            persisted_models = (
                self._session
                .execute(statement)
                .scalars()
                .all()
            )

            for persisted in persisted_models:
                incoming = indicators_by_id[
                    persisted.id
                ]

                if (
                    incoming.created_at
                    != persisted.created_at
                ):
                    raise (
                        CanonicalWebIndicatorConflictError(
                            "created_at cannot change "
                            "for an existing canonical "
                            "Web indicator"
                        )
                    )

                if (
                    incoming.updated_at
                    < persisted.updated_at
                ):
                    raise (
                        CanonicalWebIndicatorConflictError(
                            "Stale canonical Web "
                            "indicator update"
                        )
                    )

                if (
                    incoming.indicator_type
                    != persisted.indicator_type
                    or incoming.canonical_value
                    != persisted.canonical_value
                    or incoming.value_hash
                    != persisted.value_hash
                    or incoming.hostname
                    != persisted.hostname
                    or (
                        incoming
                        .canonicalization_version
                        != persisted
                        .canonicalization_version
                    )
                ):
                    raise (
                        CanonicalWebIndicatorConflictError(
                            "Canonical Web identity "
                            "cannot change"
                        )
                    )

    def _upsert_parent_rows(
        self,
        rows: Sequence[
            dict[str, Any]
        ],
    ) -> None:
        for batch in self._chunked(
            rows,
            self.WRITE_BATCH_SIZE,
        ):
            statement = insert(
                CanonicalWebIndicatorModel
            ).values(
                batch
            )

            excluded = statement.excluded

            identity_is_unchanged = and_(
                CanonicalWebIndicatorModel
                .indicator_type
                == excluded.indicator_type,
                CanonicalWebIndicatorModel
                .canonical_value
                == excluded.canonical_value,
                CanonicalWebIndicatorModel
                .value_hash
                == excluded.value_hash,
                CanonicalWebIndicatorModel
                .hostname
                == excluded.hostname,
                CanonicalWebIndicatorModel
                .canonicalization_version
                == excluded
                .canonicalization_version,
                CanonicalWebIndicatorModel
                .created_at
                == excluded.created_at,
                CanonicalWebIndicatorModel
                .updated_at
                <= excluded.updated_at,
            )

            statement = (
                statement
                .on_conflict_do_update(
                    index_elements=[
                        CanonicalWebIndicatorModel.id,
                    ],
                    set_={
                        "updated_at": (
                            excluded.updated_at
                        ),
                    },
                    where=identity_is_unchanged,
                )
                .returning(
                    CanonicalWebIndicatorModel.id
                )
            )

            returned_ids = set(
                self._session
                .execute(statement)
                .scalars()
            )

            expected_ids = {
                UUID(
                    str(
                        row["id"]
                    )
                )
                for row in batch
            }

            if returned_ids != expected_ids:
                raise (
                    CanonicalWebIndicatorConflictError(
                        "Canonical Web indicator "
                        "changed concurrently"
                    )
                )

    def _upsert_observation_rows(
        self,
        rows: Sequence[
            dict[str, Any]
        ],
    ) -> None:
        for batch in self._chunked(
            rows,
            self.WRITE_BATCH_SIZE,
        ):
            statement = insert(
                CanonicalWebIndicatorObservationModel
            ).values(
                batch
            )

            excluded = statement.excluded

            incoming_is_latest = or_(
                excluded.last_observed_at
                > (
                    CanonicalWebIndicatorObservationModel
                    .last_observed_at
                ),
                and_(
                    excluded.last_observed_at
                    == (
                        CanonicalWebIndicatorObservationModel
                        .last_observed_at
                    ),
                    cast(
                        excluded.normalized_record_id,
                        String,
                    )
                    >= cast(
                        CanonicalWebIndicatorObservationModel
                        .normalized_record_id,
                        String,
                    ),
                ),
            )

            statement = (
                statement
                .on_conflict_do_update(
                    index_elements=[
                        (
                            CanonicalWebIndicatorObservationModel
                            .source
                        ),
                        (
                            CanonicalWebIndicatorObservationModel
                            .source_record_key
                        ),
                    ],
                    set_={
                        "normalized_record_id": case(
                            (
                                incoming_is_latest,
                                excluded
                                .normalized_record_id,
                            ),
                            else_=(
                                CanonicalWebIndicatorObservationModel
                                .normalized_record_id
                            ),
                        ),
                        "observed_at": func.least(
                            CanonicalWebIndicatorObservationModel
                            .observed_at,
                            excluded.observed_at,
                        ),
                        "last_observed_at": (
                            func.greatest(
                                CanonicalWebIndicatorObservationModel
                                .last_observed_at,
                                excluded
                                .last_observed_at,
                            )
                        ),
                        "normalizer_version": case(
                            (
                                incoming_is_latest,
                                excluded
                                .normalizer_version,
                            ),
                            else_=(
                                CanonicalWebIndicatorObservationModel
                                .normalizer_version
                            ),
                        ),
                        "source_status": case(
                            (
                                incoming_is_latest,
                                excluded.source_status,
                            ),
                            else_=(
                                CanonicalWebIndicatorObservationModel
                                .source_status
                            ),
                        ),
                        "is_active": case(
                            (
                                incoming_is_latest,
                                excluded.is_active,
                            ),
                            else_=(
                                CanonicalWebIndicatorObservationModel
                                .is_active
                            ),
                        ),
                        "labels": case(
                            (
                                incoming_is_latest,
                                excluded.labels,
                            ),
                            else_=(
                                CanonicalWebIndicatorObservationModel
                                .labels
                            ),
                        ),
                    },
                    where=(
                        CanonicalWebIndicatorObservationModel
                        .indicator_id
                        == excluded.indicator_id
                    ),
                )
                .returning(
                    CanonicalWebIndicatorObservationModel
                    .source,
                    CanonicalWebIndicatorObservationModel
                    .source_record_key,
                )
            )

            returned_keys = {
                (
                    source,
                    source_record_key,
                )
                for (
                    source,
                    source_record_key,
                ) in self._session.execute(
                    statement
                )
            }

            expected_keys = {
                (
                    str(
                        row["source"]
                    ),
                    str(
                        row[
                            "source_record_key"
                        ]
                    ),
                )
                for row in batch
            }

            if returned_keys != expected_keys:
                raise (
                    CanonicalWebIndicatorConflictError(
                        "Canonical Web observation "
                        "ownership changed concurrently"
                    )
                )

    def _find_identity_owners(
        self,
        keys: Sequence[
            WebIndicatorIdentityKey
        ],
        *,
        for_update: bool,
    ) -> dict[
        WebIndicatorIdentityKey,
        UUID,
    ]:
        owners: dict[
            WebIndicatorIdentityKey,
            UUID,
        ] = {}

        for batch in self._chunked(
            sorted(
                keys
            ),
            self.LOOKUP_BATCH_SIZE,
        ):
            statement = (
                select(
                    CanonicalWebIndicatorModel
                    .canonicalization_version,
                    CanonicalWebIndicatorModel
                    .value_hash,
                    CanonicalWebIndicatorModel.id,
                )
                .where(
                    tuple_(
                        CanonicalWebIndicatorModel
                        .canonicalization_version,
                        CanonicalWebIndicatorModel
                        .value_hash,
                    ).in_(
                        batch
                    )
                )
                .order_by(
                    CanonicalWebIndicatorModel
                    .canonicalization_version,
                    CanonicalWebIndicatorModel
                    .value_hash,
                )
            )

            if for_update:
                statement = (
                    statement.with_for_update()
                )

            rows = self._session.execute(
                statement
            )

            for (
                canonicalization_version,
                value_hash,
                indicator_id,
            ) in rows:
                owners[
                    (
                        canonicalization_version,
                        value_hash,
                    )
                ] = indicator_id

        return owners

    def _find_observation_owners(
        self,
        keys: Sequence[
            WebIndicatorObservationKey
        ],
        *,
        for_update: bool,
    ) -> dict[
        WebIndicatorObservationKey,
        UUID,
    ]:
        owners: dict[
            WebIndicatorObservationKey,
            UUID,
        ] = {}

        for batch in self._chunked(
            sorted(
                keys
            ),
            self.LOOKUP_BATCH_SIZE,
        ):
            statement = (
                select(
                    CanonicalWebIndicatorObservationModel
                    .source,
                    CanonicalWebIndicatorObservationModel
                    .source_record_key,
                    CanonicalWebIndicatorObservationModel
                    .indicator_id,
                )
                .where(
                    tuple_(
                        CanonicalWebIndicatorObservationModel
                        .source,
                        CanonicalWebIndicatorObservationModel
                        .source_record_key,
                    ).in_(
                        batch
                    )
                )
                .order_by(
                    CanonicalWebIndicatorObservationModel
                    .source,
                    CanonicalWebIndicatorObservationModel
                    .source_record_key,
                )
            )

            if for_update:
                statement = (
                    statement.with_for_update()
                )

            rows = self._session.execute(
                statement
            )

            for (
                source,
                source_record_key,
                indicator_id,
            ) in rows:
                owners[
                    (
                        source,
                        source_record_key,
                    )
                ] = indicator_id

        return owners

    @staticmethod
    def _validate_identity_ownership(
        *,
        existing_owners: dict[
            WebIndicatorIdentityKey,
            UUID,
        ],
        requested_owners: dict[
            WebIndicatorIdentityKey,
            UUID,
        ],
    ) -> None:
        for key, existing_owner in (
            existing_owners.items()
        ):
            requested_owner = (
                requested_owners[key]
            )

            if existing_owner != requested_owner:
                raise (
                    CanonicalWebIndicatorConflictError(
                        "Canonical URL identity "
                        "already belongs to another "
                        "aggregate"
                    )
                )

    @staticmethod
    def _validate_observation_ownership(
        *,
        existing_owners: dict[
            WebIndicatorObservationKey,
            UUID,
        ],
        requested_owners: dict[
            WebIndicatorObservationKey,
            UUID,
        ],
    ) -> None:
        for key, existing_owner in (
            existing_owners.items()
        ):
            requested_owner = (
                requested_owners[key]
            )

            if existing_owner != requested_owner:
                raise (
                    CanonicalWebIndicatorConflictError(
                        "Canonical Web observation "
                        "already belongs to another "
                        "aggregate"
                    )
                )

    @classmethod
    def _normalize_indicators(
        cls,
        indicators: Iterable[
            CanonicalWebIndicator
        ],
    ) -> tuple[
        CanonicalWebIndicator,
        ...,
    ]:
        if isinstance(
            indicators,
            (str, bytes),
        ):
            raise TypeError(
                "indicators must be an iterable "
                "of CanonicalWebIndicator objects"
            )

        try:
            values = tuple(
                indicators
            )

        except TypeError as error:
            raise TypeError(
                "indicators must be an iterable "
                "of CanonicalWebIndicator objects"
            ) from error

        by_id: dict[
            UUID,
            CanonicalWebIndicator,
        ] = {}

        identity_owners: dict[
            WebIndicatorIdentityKey,
            UUID,
        ] = {}

        observation_owners: dict[
            WebIndicatorObservationKey,
            UUID,
        ] = {}

        ordered: list[
            CanonicalWebIndicator
        ] = []

        for indicator in values:
            if not isinstance(
                indicator,
                CanonicalWebIndicator,
            ):
                raise TypeError(
                    "Every indicator must be a "
                    "CanonicalWebIndicator"
                )

            previous = by_id.get(
                indicator.id
            )

            if (
                previous is not None
                and previous != indicator
            ):
                raise ValueError(
                    "Duplicate indicator UUID has "
                    "inconsistent snapshots"
                )

            if previous is not None:
                continue

            identity_key = (
                cls._identity_key_from_aggregate(
                    indicator
                )
            )

            identity_owner = (
                identity_owners.get(
                    identity_key
                )
            )

            if (
                identity_owner is not None
                and identity_owner
                != indicator.id
            ):
                raise (
                    CanonicalWebIndicatorConflictError(
                        "One canonical URL identity "
                        "is assigned to several "
                        "aggregates"
                    )
                )

            identity_owners[
                identity_key
            ] = indicator.id

            for observation in (
                indicator.observations
            ):
                observation_owner = (
                    observation_owners.get(
                        observation.key
                    )
                )

                if (
                    observation_owner is not None
                    and observation_owner
                    != indicator.id
                ):
                    raise (
                        CanonicalWebIndicatorConflictError(
                            "One source observation "
                            "is assigned to several "
                            "aggregates"
                        )
                    )

                observation_owners[
                    observation.key
                ] = indicator.id

            by_id[
                indicator.id
            ] = indicator

            ordered.append(
                indicator
            )

        return tuple(
            ordered
        )

    @staticmethod
    def _normalize_identity_keys(
        identities: Iterable[
            CanonicalURLIdentity
        ],
    ) -> tuple[
        WebIndicatorIdentityKey,
        ...,
    ]:
        if isinstance(
            identities,
            (str, bytes),
        ):
            raise TypeError(
                "identities must be an iterable "
                "of CanonicalURLIdentity objects"
            )

        try:
            values = tuple(
                identities
            )

        except TypeError as error:
            raise TypeError(
                "identities must be an iterable "
                "of CanonicalURLIdentity objects"
            ) from error

        keys: list[
            WebIndicatorIdentityKey
        ] = []

        seen: set[
            WebIndicatorIdentityKey
        ] = set()

        for identity in values:
            if not isinstance(
                identity,
                CanonicalURLIdentity,
            ):
                raise TypeError(
                    "Every identity must be a "
                    "CanonicalURLIdentity"
                )

            key = (
                identity
                .canonicalization_version,
                identity.value_hash,
            )

            if key not in seen:
                seen.add(
                    key
                )

                keys.append(
                    key
                )

        return tuple(
            keys
        )

    @staticmethod
    def _normalize_observation_keys(
        observations: Iterable[
            WebIndicatorObservation
        ],
    ) -> tuple[
        WebIndicatorObservationKey,
        ...,
    ]:
        if isinstance(
            observations,
            (str, bytes),
        ):
            raise TypeError(
                "observations must be an iterable "
                "of WebIndicatorObservation objects"
            )

        try:
            values = tuple(
                observations
            )

        except TypeError as error:
            raise TypeError(
                "observations must be an iterable "
                "of WebIndicatorObservation objects"
            ) from error

        keys: list[
            WebIndicatorObservationKey
        ] = []

        seen: set[
            WebIndicatorObservationKey
        ] = set()

        for observation in values:
            if not isinstance(
                observation,
                WebIndicatorObservation,
            ):
                raise TypeError(
                    "Every observation must be a "
                    "WebIndicatorObservation"
                )

            if observation.key not in seen:
                seen.add(
                    observation.key
                )

                keys.append(
                    observation.key
                )

        return tuple(
            keys
        )

    @classmethod
    def _normalize_uuid_iterable(
        cls,
        values: Iterable[UUID],
        *,
        field_name: str,
    ) -> tuple[UUID, ...]:
        if isinstance(
            values,
            (str, bytes),
        ):
            raise TypeError(
                f"{field_name} must be an "
                "iterable of UUID objects"
            )

        try:
            candidates = tuple(
                values
            )

        except TypeError as error:
            raise TypeError(
                f"{field_name} must be an "
                "iterable of UUID objects"
            ) from error

        normalized: list[UUID] = []
        seen: set[UUID] = set()

        for candidate in candidates:
            value = cls._normalize_uuid(
                candidate,
                field_name=field_name,
            )

            if value not in seen:
                seen.add(
                    value
                )

                normalized.append(
                    value
                )

        return tuple(
            normalized
        )

    @staticmethod
    def _normalize_uuid(
        value: UUID,
        *,
        field_name: str,
    ) -> UUID:
        if not isinstance(
            value,
            UUID,
        ):
            raise TypeError(
                f"{field_name} must be a UUID"
            )

        if value.int == 0:
            raise ValueError(
                f"{field_name} must not be "
                "the nil UUID"
            )

        return value

    @staticmethod
    def _identity_key_from_aggregate(
        indicator: CanonicalWebIndicator,
    ) -> WebIndicatorIdentityKey:
        return (
            indicator.canonicalization_version,
            indicator.value_hash,
        )

    @staticmethod
    def _parent_row(
        indicator: CanonicalWebIndicator,
    ) -> dict[str, Any]:
        return {
            "id": indicator.id,
            "indicator_type": (
                indicator.indicator_type
            ),
            "canonical_value": (
                indicator.canonical_value
            ),
            "value_hash": indicator.value_hash,
            "hostname": indicator.hostname,
            "canonicalization_version": (
                indicator
                .canonicalization_version
            ),
            "created_at": indicator.created_at,
            "updated_at": indicator.updated_at,
        }

    @staticmethod
    def _observation_row(
        *,
        indicator_id: UUID,
        observation: (
            WebIndicatorObservation
        ),
    ) -> dict[str, Any]:
        return {
            "id": uuid4(),
            "indicator_id": indicator_id,
            "source": observation.source,
            "source_record_key": (
                observation
                .source_record_key
            ),
            "normalized_record_id": (
                observation
                .normalized_record_id
            ),
            "observed_at": (
                observation.observed_at
            ),
            "last_observed_at": (
                observation
                .last_observed_at
                or observation.observed_at
            ),
            "normalizer_version": (
                observation
                .normalizer_version
            ),
            "source_status": (
                observation.source_status
            ),
            "is_active": (
                observation.is_active
            ),
            "labels": list(
                observation.labels
            ),
        }

    @staticmethod
    def _to_observation(
        model: (
            CanonicalWebIndicatorObservationModel
        ),
    ) -> WebIndicatorObservation:
        return WebIndicatorObservation(
            source=model.source,
            source_record_key=(
                model.source_record_key
            ),
            normalized_record_id=(
                model.normalized_record_id
            ),
            observed_at=model.observed_at,
            last_observed_at=(
                model.last_observed_at
            ),
            normalizer_version=(
                model.normalizer_version
            ),
            source_status=(
                model.source_status
            ),
            is_active=model.is_active,
            labels=tuple(
                model.labels
            ),
        )

    @staticmethod
    def _chunked(
        values: Sequence[_T],
        size: int,
    ) -> Iterator[
        Sequence[_T]
    ]:
        for index in range(
            0,
            len(values),
            size,
        ):
            yield values[
                index:index + size
            ]