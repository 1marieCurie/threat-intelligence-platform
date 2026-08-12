from __future__ import annotations

from sqlalchemy import (
    exists,
    func,
    literal,
    select,
    tuple_,
)
from sqlalchemy.orm import (
    Session,
    aliased,
)

from application.models.canonical_threat_url_candidate import (
    CanonicalThreatURLCandidate,
    CanonicalThreatURLCursor,
    ThreatURLLabel,
    ThreatURLSource,
)
from application.ports.outbound.canonical_threat_url_source import (
    CanonicalThreatURLSource,
)
from infrastructure.persistence.models.canonical_web import (
    CanonicalWebIndicatorModel,
    CanonicalWebIndicatorObservationModel,
)


class SqlAlchemyCanonicalThreatURLSource(
    CanonicalThreatURLSource
):
    """
    Reader borné des URLs canoniques utilisées
    comme candidats phishing ou malware.

    Politique V1 :
    - phishing -> PhishTank exclusivement ;
    - malware -> URLhaus exclusivement ;
    - présence dans les deux sources -> exclusion ;
    - aucune valeur URL n'est journalisée ;
    - aucun accès réseau.
    """

    DEFAULT_BATCH_SIZE = 500
    MAX_BATCH_SIZE = 1_000

    _SOURCE_BY_LABEL: dict[
        ThreatURLLabel,
        ThreatURLSource,
    ] = {
        "phishing": "phishtank",
        "malware": "urlhaus",
    }

    _OTHER_SOURCE_BY_LABEL: dict[
        ThreatURLLabel,
        ThreatURLSource,
    ] = {
        "phishing": "urlhaus",
        "malware": "phishtank",
    }

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

    def read_batch(
        self,
        *,
        label_code: ThreatURLLabel,
        after_cursor: (
            CanonicalThreatURLCursor
            | None
        ) = None,
        limit: int = DEFAULT_BATCH_SIZE,
    ) -> tuple[
        CanonicalThreatURLCandidate,
        ...,
    ]:
        normalized_label = (
            self._validate_label(
                label_code
            )
        )

        normalized_limit = (
            self._validate_limit(
                limit
            )
        )

        normalized_cursor = (
            self._validate_cursor(
                after_cursor
            )
        )

        source = (
            self._SOURCE_BY_LABEL[
                normalized_label
            ]
        )

        other_source = (
            self._OTHER_SOURCE_BY_LABEL[
                normalized_label
            ]
        )

        source_exists_observation = aliased(
            CanonicalWebIndicatorObservationModel
        )

        other_source_observation = aliased(
            CanonicalWebIndicatorObservationModel
        )

        source_time_observation = aliased(
            CanonicalWebIndicatorObservationModel
        )

        has_source = exists(
            select(1)
            .select_from(
                source_exists_observation
            )
            .where(
                source_exists_observation.indicator_id
                == CanonicalWebIndicatorModel.id,
                source_exists_observation.source
                == source,
            )
        )

        has_other_source = exists(
            select(1)
            .select_from(
                other_source_observation
            )
            .where(
                other_source_observation.indicator_id
                == CanonicalWebIndicatorModel.id,
                other_source_observation.source
                == other_source,
            )
        )

        first_observed_at = (
            select(
                func.min(
                    source_time_observation
                    .observed_at
                )
            )
            .where(
                source_time_observation.indicator_id
                == CanonicalWebIndicatorModel.id,
                source_time_observation.source
                == source,
            )
            .scalar_subquery()
        )

        statement = (
            select(
                CanonicalWebIndicatorModel.id,
                CanonicalWebIndicatorModel
                .canonical_value,
                CanonicalWebIndicatorModel
                .value_hash,
                CanonicalWebIndicatorModel
                .hostname,
                CanonicalWebIndicatorModel
                .canonicalization_version,
                first_observed_at.label(
                    "observed_at"
                ),
            )
            .where(
                has_source,
                ~has_other_source,
            )
        )

        if normalized_cursor is not None:
            statement = statement.where(
                tuple_(
                    CanonicalWebIndicatorModel
                    .canonicalization_version,
                    CanonicalWebIndicatorModel
                    .value_hash,
                    CanonicalWebIndicatorModel
                    .id,
                )
                > tuple_(
                    literal(
                        normalized_cursor
                        .canonicalization_version
                    ),
                    literal(
                        normalized_cursor
                        .value_hash
                    ),
                    literal(
                        normalized_cursor
                        .indicator_id
                    ),
                )
            )

        statement = (
            statement
            .order_by(
                CanonicalWebIndicatorModel
                .canonicalization_version
                .asc(),
                CanonicalWebIndicatorModel
                .value_hash
                .asc(),
                CanonicalWebIndicatorModel
                .id
                .asc(),
            )
            .limit(
                normalized_limit
            )
        )

        rows = (
            self._session
            .execute(
                statement
            )
            .tuples()
            .all()
        )

        candidates: list[
            CanonicalThreatURLCandidate
        ] = []

        for (
            indicator_id,
            canonical_value,
            value_hash,
            hostname,
            canonicalization_version,
            observed_at,
        ) in rows:
            if observed_at is None:
                raise RuntimeError(
                    "Canonical threat observation "
                    "timestamp is missing"
                )

            candidates.append(
                CanonicalThreatURLCandidate(
                    canonical_web_indicator_id=(
                        indicator_id
                    ),
                    canonical_value=(
                        canonical_value
                    ),
                    value_hash=value_hash,
                    hostname=hostname,
                    canonicalization_version=(
                        canonicalization_version
                    ),
                    source=source,
                    label_code=(
                        normalized_label
                    ),
                    observed_at=(
                        observed_at
                    ),
                )
            )

        return tuple(
            candidates
        )

    @classmethod
    def _validate_limit(
        cls,
        value: int,
    ) -> int:
        if (
            isinstance(
                value,
                bool,
            )
            or not isinstance(
                value,
                int,
            )
        ):
            raise TypeError(
                "limit must be an integer"
            )

        if not (
            1
            <= value
            <= cls.MAX_BATCH_SIZE
        ):
            raise ValueError(
                "limit must be between 1 "
                f"and {cls.MAX_BATCH_SIZE}"
            )

        return value

    @staticmethod
    def _validate_label(
        value: ThreatURLLabel,
    ) -> ThreatURLLabel:
        if value not in (
            "phishing",
            "malware",
        ):
            raise ValueError(
                "Unsupported threat URL label"
            )

        return value

    @staticmethod
    def _validate_cursor(
        value: (
            CanonicalThreatURLCursor
            | None
        ),
    ) -> (
        CanonicalThreatURLCursor
        | None
    ):
        if value is None:
            return None

        if not isinstance(
            value,
            CanonicalThreatURLCursor,
        ):
            raise TypeError(
                "after_cursor must be a "
                "CanonicalThreatURLCursor or None"
            )

        return value