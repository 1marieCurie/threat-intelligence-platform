from __future__ import annotations

from sqlalchemy import (
    literal,
    select,
    tuple_,
)
from sqlalchemy.orm import Session

from application.models.urlhaus_canonical_source_record import (
    URLhausCanonicalCursor,
    URLhausCanonicalSourceRecord,
)
from application.ports.outbound.urlhaus_canonical_source import (
    URLhausCanonicalSource,
)
from infrastructure.persistence.models.normalized_urlhaus import (
    URLhausURLModel,
)


class SqlAlchemyURLhausCanonicalSource(
    URLhausCanonicalSource
):
    """
    Reader keyset des observations URLhaus normalisées.

    Aucun tag, blacklist, reporter ou payload brut n'est
    chargé dans le pipeline canonique V1.
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
            URLhausCanonicalCursor
            | None
        ) = None,
        limit: int = DEFAULT_BATCH_SIZE,
    ) -> tuple[
        URLhausCanonicalSourceRecord,
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
            URLhausURLModel.id,
            URLhausURLModel.urlhaus_id,
            URLhausURLModel.malicious_url,
            URLhausURLModel.normalized_at,
            URLhausURLModel.normalizer_version,
            URLhausURLModel.date_added,
            URLhausURLModel.url_status,
        )

        if normalized_cursor is not None:
            statement = statement.where(
                tuple_(
                    URLhausURLModel.urlhaus_id,
                    URLhausURLModel.id,
                )
                > tuple_(
                    literal(
                        normalized_cursor
                        .urlhaus_id
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
                URLhausURLModel
                .urlhaus_id
                .asc(),
                URLhausURLModel
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
            URLhausCanonicalSourceRecord(
                normalized_record_id=(
                    normalized_record_id
                ),
                urlhaus_id=urlhaus_id,
                malicious_url=malicious_url,
                normalized_at=normalized_at,
                normalizer_version=(
                    normalizer_version
                ),
                date_added=date_added,
                url_status=url_status,
            )
            for (
                normalized_record_id,
                urlhaus_id,
                malicious_url,
                normalized_at,
                normalizer_version,
                date_added,
                url_status,
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
            URLhausCanonicalCursor
            | None
        ),
    ) -> (
        URLhausCanonicalCursor
        | None
    ):
        if value is None:
            return None

        if not isinstance(
            value,
            URLhausCanonicalCursor,
        ):
            raise TypeError(
                "after_cursor must be a "
                "URLhausCanonicalCursor or None"
            )

        return value