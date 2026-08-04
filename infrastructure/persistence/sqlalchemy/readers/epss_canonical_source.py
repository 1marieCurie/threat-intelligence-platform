from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from application.models.epss_canonical_source_record import (
    EPSSCanonicalSourceRecord,
)
from application.models.epss_snapshot import (
    EPSSSnapshot,
)
from application.ports.outbound.epss_canonical_source import (
    EPSSCanonicalSource,
)
from domain.vulnerability_identifier import (
    VulnerabilityIdentifier,
)
from infrastructure.persistence.models.normalized import (
    EPSSScoreModel,
)


class SqlAlchemyEPSSCanonicalSource(
    EPSSCanonicalSource
):
    """
    Reader PostgreSQL des projections EPSS canoniques.

    La requête :

    - utilise une pagination keyset sur cve_id ;
    - sélectionne uniquement six colonnes normalisées ;
    - ne charge pas d'instance ORM complète ;
    - n'accède jamais au schéma raw.
    """

    DEFAULT_BATCH_SIZE = 500
    MAX_BATCH_SIZE = 1_000

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
        after_cve_id: str | None = None,
        limit: int = DEFAULT_BATCH_SIZE,
    ) -> tuple[
        EPSSCanonicalSourceRecord,
        ...,
    ]:
        normalized_limit = (
            self._validate_limit(
                limit
            )
        )

        normalized_cursor = (
            self._normalize_cursor(
                after_cve_id
            )
        )

        statement = select(
            EPSSScoreModel.cve_id,
            EPSSScoreModel.epss_score,
            EPSSScoreModel.percentile,
            EPSSScoreModel.score_date,
            EPSSScoreModel.api_version,
            EPSSScoreModel.synchronized_at,
        )

        if normalized_cursor is not None:
            statement = statement.where(
                EPSSScoreModel.cve_id
                > normalized_cursor
            )

        statement = (
            statement
            .order_by(
                EPSSScoreModel.cve_id.asc()
            )
            .limit(
                normalized_limit
            )
        )

        rows = (
            self._session
            .execute(statement)
            .tuples()
            .all()
        )

        return tuple(
            EPSSCanonicalSourceRecord(
                cve_id=cve_id,
                snapshot=EPSSSnapshot(
                    score=epss_score,
                    percentile=percentile,
                    score_date=score_date,
                    api_version=api_version,
                ),
                synchronized_at=(
                    synchronized_at
                ),
            )
            for (
                cve_id,
                epss_score,
                percentile,
                score_date,
                api_version,
                synchronized_at,
            )
            in rows
        )

    @classmethod
    def _validate_limit(
        cls,
        value: int,
    ) -> int:
        if (
            isinstance(value, bool)
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
    def _normalize_cursor(
        value: str | None,
    ) -> str | None:
        if value is None:
            return None

        return VulnerabilityIdentifier(
            namespace="CVE",
            value=value,
            is_primary=True,
        ).value