from __future__ import annotations

from sqlalchemy import (
    select,
    tuple_,
    literal,
)
from sqlalchemy.orm import Session

from application.models.cisa_kev_canonical_source_record import (
    CisaKevCanonicalCursor,
    CisaKevCanonicalSourceRecord,
)
from application.ports.outbound.cisa_kev_canonical_source import (
    CisaKevCanonicalSource,
)
from infrastructure.persistence.models.normalized import (
    CisaKevVulnerabilityModel,
)


class SqlAlchemyCisaKevCanonicalSource(
    CisaKevCanonicalSource
):
    """
    Reader PostgreSQL des projections CISA KEV.

    Il sélectionne uniquement les quatre colonnes
    nécessaires à la corrélation canonique et
    n'accède jamais au schéma raw.
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
        after_cursor: (
            CisaKevCanonicalCursor
            | None
        ) = None,
        limit: int = DEFAULT_BATCH_SIZE,
    ) -> tuple[
        CisaKevCanonicalSourceRecord,
        ...,
    ]:
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

        statement = select(
            CisaKevVulnerabilityModel.id,
            CisaKevVulnerabilityModel.cve_id,
            CisaKevVulnerabilityModel.date_added,
            CisaKevVulnerabilityModel.normalized_at,
        )

        if normalized_cursor is not None:
            statement = statement.where(
                tuple_(
                    CisaKevVulnerabilityModel.cve_id,
                    CisaKevVulnerabilityModel.id,
                )
                > tuple_(
                    literal(
                        normalized_cursor.cve_id
                    ),
                    literal(
                        normalized_cursor.normalized_record_id
                    ),
                )
            )

        statement = (
            statement
            .order_by(
                CisaKevVulnerabilityModel
                .cve_id
                .asc(),
                CisaKevVulnerabilityModel
                .id
                .asc(),
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
            CisaKevCanonicalSourceRecord(
                normalized_record_id=(
                    normalized_record_id
                ),
                cve_id=cve_id,
                date_added=date_added,
                normalized_at=normalized_at,
            )
            for (
                normalized_record_id,
                cve_id,
                date_added,
                normalized_at,
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
    def _validate_cursor(
        value: (
            CisaKevCanonicalCursor
            | None
        ),
    ) -> (
        CisaKevCanonicalCursor
        | None
    ):
        if value is None:
            return None

        if not isinstance(
            value,
            CisaKevCanonicalCursor,
        ):
            raise TypeError(
                "after_cursor must be a "
                "CisaKevCanonicalCursor or None"
            )

        return value