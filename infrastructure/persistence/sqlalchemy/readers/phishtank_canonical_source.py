from __future__ import annotations

from sqlalchemy import (
    literal,
    select,
    tuple_,
)
from sqlalchemy.orm import Session

from application.models.phishtank_canonical_source_record import (
    PhishTankCanonicalCursor,
    PhishTankCanonicalSourceRecord,
)
from application.ports.outbound.phishtank_canonical_source import (
    PhishTankCanonicalSource,
)
from infrastructure.persistence.models.normalized_phishtank import (
    PhishTankPhishingModel,
)


class SqlAlchemyPhishTankCanonicalSource(
    PhishTankCanonicalSource
):
    """
    Reader keyset des observations PhishTank normalisées.

    Seules les colonnes nécessaires à la canonicalisation
    sont sélectionnées. Aucun payload brut ou détail réseau
    n'est chargé.
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
            PhishTankCanonicalCursor
            | None
        ) = None,
        limit: int = DEFAULT_BATCH_SIZE,
    ) -> tuple[
        PhishTankCanonicalSourceRecord,
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
            PhishTankPhishingModel.id,
            PhishTankPhishingModel.phish_id,
            PhishTankPhishingModel.phishing_url,
            PhishTankPhishingModel.normalized_at,
            PhishTankPhishingModel.normalizer_version,
            PhishTankPhishingModel.submission_time,
            PhishTankPhishingModel.verification_time,
            PhishTankPhishingModel.verified,
            PhishTankPhishingModel.online,
        )

        if normalized_cursor is not None:
            statement = statement.where(
                tuple_(
                    PhishTankPhishingModel.phish_id,
                    PhishTankPhishingModel.id,
                )
                > tuple_(
                    literal(
                        normalized_cursor.phish_id
                    ),
                    literal(
                        normalized_cursor
                        .normalized_record_id
                    ),
                )
            )

        statement = (
            statement
            .order_by(
                PhishTankPhishingModel
                .phish_id
                .asc(),
                PhishTankPhishingModel
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
            PhishTankCanonicalSourceRecord(
                normalized_record_id=(
                    normalized_record_id
                ),
                phish_id=phish_id,
                phishing_url=phishing_url,
                normalized_at=normalized_at,
                normalizer_version=(
                    normalizer_version
                ),
                submission_time=(
                    submission_time
                ),
                verification_time=(
                    verification_time
                ),
                verified=verified,
                online=online,
            )
            for (
                normalized_record_id,
                phish_id,
                phishing_url,
                normalized_at,
                normalizer_version,
                submission_time,
                verification_time,
                verified,
                online,
            ) in rows
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
            PhishTankCanonicalCursor
            | None
        ),
    ) -> (
        PhishTankCanonicalCursor
        | None
    ):
        if value is None:
            return None

        if not isinstance(
            value,
            PhishTankCanonicalCursor,
        ):
            raise TypeError(
                "after_cursor must be a "
                "PhishTankCanonicalCursor or None"
            )

        return value