from __future__ import annotations

from collections import OrderedDict
from collections.abc import (
    Callable,
    Iterable,
    Sequence,
)
from dataclasses import dataclass
from datetime import (
    UTC,
    datetime,
)
from uuid import (
    UUID,
    uuid4,
)

from application.models.canonical_url_identity import (
    CanonicalURLIdentity,
)
from application.models.canonical_web_indicator_observation import (
    CanonicalWebIndicatorObservation,
)
from application.ports.outbound.canonical_web_indicator_repository import (
    WebIndicatorIdentityKey,
    WebIndicatorObservationKey,
)
from application.ports.outbound.canonical_web_indicator_unit_of_work import (
    CanonicalWebIndicatorUnitOfWork,
)
from domain.canonical_web_indicator import (
    CanonicalWebIndicator,
)
from domain.web_indicator_observation import (
    WebIndicatorObservation,
)


class CanonicalWebCorrelationError(
    RuntimeError
):
    """
    Erreur générique de corrélation canonique Web.
    """


class CanonicalWebCorrelationConflictError(
    CanonicalWebCorrelationError
):
    """
    Signale une corrélation exacte ambiguë.

    La V1 ne déplace et ne fusionne jamais automatiquement
    deux agrégats persistés.
    """


@dataclass(
    frozen=True,
    slots=True,
)
class CanonicalWebCorrelationResult:
    observations_received: int
    components_built: int
    created: int
    updated: int
    persisted: int

    aggregates: tuple[
        CanonicalWebIndicator,
        ...,
    ]


class CanonicalWebIndicatorCorrelationService:
    """
    Corrèle les observations PhishTank et URLhaus.

    Règles V1 :

    - identité exacte par empreinte d'URL canonique ;
    - identité exacte d'une observation source ;
    - aucune corrélation par hostname ;
    - aucune corrélation par adresse IP ;
    - aucune similarité textuelle ;
    - aucune fusion automatique entre agrégats existants ;
    - traitement borné en mémoire.
    """

    DEFAULT_MAX_OBSERVATIONS = 5_000

    def __init__(
        self,
        *,
        unit_of_work: (
            CanonicalWebIndicatorUnitOfWork
        ),
        uuid_factory: Callable[
            [],
            UUID,
        ] = uuid4,
        clock: Callable[
            [],
            datetime,
        ] = lambda: datetime.now(
            UTC
        ),
        max_observations: int = (
            DEFAULT_MAX_OBSERVATIONS
        ),
    ) -> None:
        if unit_of_work is None:
            raise ValueError(
                "unit_of_work must not be None"
            )

        if not callable(
            uuid_factory
        ):
            raise TypeError(
                "uuid_factory must be callable"
            )

        if not callable(
            clock
        ):
            raise TypeError(
                "clock must be callable"
            )

        if (
            isinstance(
                max_observations,
                bool,
            )
            or not isinstance(
                max_observations,
                int,
            )
        ):
            raise TypeError(
                "max_observations must be "
                "an integer"
            )

        if max_observations < 1:
            raise ValueError(
                "max_observations must be "
                "greater than zero"
            )

        self._unit_of_work = unit_of_work
        self._uuid_factory = uuid_factory
        self._clock = clock
        self._max_observations = (
            max_observations
        )

    def correlate(
        self,
        observations: Iterable[
            CanonicalWebIndicatorObservation
        ],
    ) -> CanonicalWebCorrelationResult:
        normalized_observations = (
            self._normalize_observations(
                observations
            )
        )

        if not normalized_observations:
            return CanonicalWebCorrelationResult(
                observations_received=0,
                components_built=0,
                created=0,
                updated=0,
                persisted=0,
                aggregates=(),
            )

        if (
            len(normalized_observations)
            > self._max_observations
        ):
            raise ValueError(
                "observations exceeds the "
                "configured limit of "
                f"{self._max_observations}"
            )

        grouped_observations = (
            self._group_by_identity(
                normalized_observations
            )
        )

        identities = tuple(
            observation.identity
            for observation
            in normalized_observations
        )

        source_observations = tuple(
            observation.observation
            for observation
            in normalized_observations
        )

        with self._unit_of_work as unit_of_work:
            repository = (
                unit_of_work
                .canonical_web_indicators
            )

            aggregates_by_identity = (
                repository
                .find_many_by_identities(
                    identities
                )
            )

            aggregates_by_observation = (
                repository
                .find_many_by_observations(
                    source_observations
                )
            )

            used_ids = {
                aggregate.id
                for aggregate
                in aggregates_by_identity.values()
            }

            used_ids.update(
                aggregate.id
                for aggregate
                in aggregates_by_observation.values()
            )

            now = self._normalize_clock_value(
                self._clock()
            )

            aggregates: list[
                CanonicalWebIndicator
            ] = []

            created = 0
            updated = 0

            for (
                identity_key,
                component,
            ) in grouped_observations.items():
                identity = (
                    component[0].identity
                )

                existing = (
                    self._resolve_existing_aggregate(
                        identity=identity,
                        component=component,
                        aggregates_by_identity=(
                            aggregates_by_identity
                        ),
                        aggregates_by_observation=(
                            aggregates_by_observation
                        ),
                    )
                )

                if existing is None:
                    indicator_id = (
                        self._generate_unique_id(
                            used_ids
                        )
                    )

                    used_ids.add(
                        indicator_id
                    )

                    created += 1

                else:
                    indicator_id = (
                        existing.id
                    )

                    updated += 1

                aggregate = self._build_aggregate(
                    indicator_id=indicator_id,
                    identity=identity,
                    existing=existing,
                    observations=tuple(
                        item.observation
                        for item in component
                    ),
                    now=now,
                )

                if (
                    self._identity_key_for_aggregate(
                        aggregate
                    )
                    != identity_key
                ):
                    raise CanonicalWebCorrelationError(
                        "Built aggregate identity "
                        "does not match its component"
                    )

                aggregates.append(
                    aggregate
                )

            persisted = repository.upsert_many(
                aggregates
            )

            if persisted != len(
                aggregates
            ):
                raise CanonicalWebCorrelationError(
                    "Canonical Web repository "
                    "returned an unexpected "
                    "persisted aggregate count"
                )

            unit_of_work.commit()

        return CanonicalWebCorrelationResult(
            observations_received=len(
                normalized_observations
            ),
            components_built=len(
                grouped_observations
            ),
            created=created,
            updated=updated,
            persisted=persisted,
            aggregates=tuple(
                aggregates
            ),
        )

    @staticmethod
    def _normalize_observations(
        observations: Iterable[
            CanonicalWebIndicatorObservation
        ],
    ) -> tuple[
        CanonicalWebIndicatorObservation,
        ...,
    ]:
        if isinstance(
            observations,
            (str, bytes),
        ):
            raise TypeError(
                "observations must be an "
                "iterable of canonical "
                "Web observations"
            )

        try:
            normalized = tuple(
                observations
            )

        except TypeError as error:
            raise TypeError(
                "observations must be an "
                "iterable of canonical "
                "Web observations"
            ) from error

        for observation in normalized:
            if not isinstance(
                observation,
                CanonicalWebIndicatorObservation,
            ):
                raise TypeError(
                    "Every observation must be a "
                    "CanonicalWebIndicatorObservation"
                )

        return normalized

    @classmethod
    def _group_by_identity(
        cls,
        observations: Sequence[
            CanonicalWebIndicatorObservation
        ],
    ) -> OrderedDict[
        WebIndicatorIdentityKey,
        list[
            CanonicalWebIndicatorObservation
        ],
    ]:
        groups: OrderedDict[
            WebIndicatorIdentityKey,
            list[
                CanonicalWebIndicatorObservation
            ],
        ] = OrderedDict()

        identities_by_observation: dict[
            WebIndicatorObservationKey,
            WebIndicatorIdentityKey,
        ] = {}

        reference_identities: dict[
            WebIndicatorIdentityKey,
            CanonicalURLIdentity,
        ] = {}

        for item in observations:
            identity_key = (
                cls._identity_key(
                    item.identity
                )
            )

            observation_key = (
                item.observation.key
            )

            previous_identity_key = (
                identities_by_observation.get(
                    observation_key
                )
            )

            if (
                previous_identity_key is not None
                and previous_identity_key
                != identity_key
            ):
                raise (
                    CanonicalWebCorrelationConflictError(
                        "One source observation "
                        "references several canonical "
                        "URL identities"
                    )
                )

            identities_by_observation[
                observation_key
            ] = identity_key

            reference_identity = (
                reference_identities.get(
                    identity_key
                )
            )

            if (
                reference_identity is not None
                and reference_identity
                != item.identity
            ):
                raise (
                    CanonicalWebCorrelationConflictError(
                        "One URL hash references "
                        "inconsistent canonical values"
                    )
                )

            reference_identities[
                identity_key
            ] = item.identity

            groups.setdefault(
                identity_key,
                [],
            ).append(
                item
            )

        return groups

    @classmethod
    def _resolve_existing_aggregate(
        cls,
        *,
        identity: CanonicalURLIdentity,
        component: Sequence[
            CanonicalWebIndicatorObservation
        ],
        aggregates_by_identity: dict[
            WebIndicatorIdentityKey,
            CanonicalWebIndicator,
        ],
        aggregates_by_observation: dict[
            WebIndicatorObservationKey,
            CanonicalWebIndicator,
        ],
    ) -> CanonicalWebIndicator | None:
        resolved: dict[
            UUID,
            CanonicalWebIndicator,
        ] = {}

        identity_aggregate = (
            aggregates_by_identity.get(
                cls._identity_key(
                    identity
                )
            )
        )

        if identity_aggregate is not None:
            cls._register_snapshot(
                resolved=resolved,
                aggregate=identity_aggregate,
            )

        for item in component:
            observation_aggregate = (
                aggregates_by_observation.get(
                    item.observation.key
                )
            )

            if observation_aggregate is not None:
                cls._register_snapshot(
                    resolved=resolved,
                    aggregate=(
                        observation_aggregate
                    ),
                )

        if len(resolved) > 1:
            raise (
                CanonicalWebCorrelationConflictError(
                    "Exact URL identity and source "
                    "observations resolve to several "
                    "canonical Web indicators"
                )
            )

        if not resolved:
            return None

        aggregate = next(
            iter(
                resolved.values()
            )
        )

        incoming_identity_key = (
            cls._identity_key(
                identity
            )
        )

        persisted_identity_key = (
            cls._identity_key_for_aggregate(
                aggregate
            )
        )

        if (
            incoming_identity_key
            != persisted_identity_key
        ):
            raise (
                CanonicalWebCorrelationConflictError(
                    "A persisted source observation "
                    "cannot be moved to another "
                    "canonical URL"
                )
            )

        if (
            aggregate.canonical_value
            != identity.canonical_value
            or aggregate.hostname
            != identity.hostname
        ):
            raise (
                CanonicalWebCorrelationConflictError(
                    "Persisted URL identity is "
                    "inconsistent with its hash"
                )
            )

        return aggregate

    @staticmethod
    def _register_snapshot(
        *,
        resolved: dict[
            UUID,
            CanonicalWebIndicator,
        ],
        aggregate: CanonicalWebIndicator,
    ) -> None:
        previous = resolved.get(
            aggregate.id
        )

        if (
            previous is not None
            and previous != aggregate
        ):
            raise CanonicalWebCorrelationError(
                "Repository returned inconsistent "
                "snapshots for one canonical UUID"
            )

        resolved[
            aggregate.id
        ] = aggregate

    @classmethod
    def _build_aggregate(
        cls,
        *,
        indicator_id: UUID,
        identity: CanonicalURLIdentity,
        existing: CanonicalWebIndicator | None,
        observations: Sequence[
            WebIndicatorObservation
        ],
        now: datetime,
    ) -> CanonicalWebIndicator:
        observations_by_key: dict[
            WebIndicatorObservationKey,
            WebIndicatorObservation,
        ] = {}

        if existing is not None:
            for observation in (
                existing.observations
            ):
                observations_by_key[
                    observation.key
                ] = observation

        for observation in observations:
            persisted = (
                observations_by_key.get(
                    observation.key
                )
            )

            if persisted is None:
                observations_by_key[
                    observation.key
                ] = observation

            else:
                observations_by_key[
                    observation.key
                ] = cls._merge_observation(
                    persisted,
                    observation,
                )

        ordered_observations = tuple(
            observations_by_key[key]
            for key in sorted(
                observations_by_key
            )
        )

        created_at = (
            now
            if existing is None
            else existing.created_at
        )

        updated_at = max(
            created_at,
            now,
            (
                existing.updated_at
                if existing is not None
                else created_at
            ),
        )

        return CanonicalWebIndicator(
            id=indicator_id,
            canonical_value=(
                identity.canonical_value
            ),
            value_hash=identity.value_hash,
            hostname=identity.hostname,
            observations=(
                ordered_observations
            ),
            created_at=created_at,
            updated_at=updated_at,
            canonicalization_version=(
                identity
                .canonicalization_version
            ),
        )

    @staticmethod
    def _merge_observation(
        current: WebIndicatorObservation,
        incoming: WebIndicatorObservation,
    ) -> WebIndicatorObservation:
        if current.key != incoming.key:
            raise CanonicalWebCorrelationError(
                "Only observations with the "
                "same source key can be merged"
            )

        current_last = (
            current.last_observed_at
            or current.observed_at
        )

        incoming_last = (
            incoming.last_observed_at
            or incoming.observed_at
        )

        current_rank = (
            current_last,
            current.normalized_record_id.hex,
        )

        incoming_rank = (
            incoming_last,
            incoming.normalized_record_id.hex,
        )

        latest = (
            incoming
            if incoming_rank >= current_rank
            else current
        )

        return WebIndicatorObservation(
            source=current.source,
            source_record_key=(
                current.source_record_key
            ),
            normalized_record_id=(
                latest.normalized_record_id
            ),
            observed_at=min(
                current.observed_at,
                incoming.observed_at,
            ),
            last_observed_at=max(
                current_last,
                incoming_last,
            ),
            normalizer_version=(
                latest.normalizer_version
            ),
            source_status=(
                latest.source_status
            ),
            is_active=latest.is_active,
            labels=latest.labels,
        )

    def _generate_unique_id(
        self,
        used_ids: set[UUID],
    ) -> UUID:
        for _ in range(100):
            candidate = self._uuid_factory()

            if not isinstance(
                candidate,
                UUID,
            ):
                raise TypeError(
                    "uuid_factory must return "
                    "a UUID"
                )

            if (
                candidate.int != 0
                and candidate not in used_ids
            ):
                return candidate

        raise CanonicalWebCorrelationError(
            "Unable to generate a unique "
            "canonical Web indicator UUID"
        )

    @staticmethod
    def _identity_key(
        identity: CanonicalURLIdentity,
    ) -> WebIndicatorIdentityKey:
        return (
            identity.canonicalization_version,
            identity.value_hash,
        )

    @staticmethod
    def _identity_key_for_aggregate(
        aggregate: CanonicalWebIndicator,
    ) -> WebIndicatorIdentityKey:
        return (
            aggregate.canonicalization_version,
            aggregate.value_hash,
        )

    @staticmethod
    def _normalize_clock_value(
        value: datetime,
    ) -> datetime:
        if not isinstance(
            value,
            datetime,
        ):
            raise TypeError(
                "clock must return a datetime"
            )

        if (
            value.tzinfo is None
            or value.utcoffset() is None
        ):
            raise ValueError(
                "clock must return a "
                "timezone-aware datetime"
            )

        return value.astimezone(
            UTC
        )