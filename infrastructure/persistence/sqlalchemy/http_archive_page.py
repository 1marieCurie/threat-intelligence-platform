from __future__ import annotations

from collections.abc import Sequence

from sqlalchemy.dialects.postgresql import (
    insert as pg_insert,
)
from sqlalchemy.orm import (
    Session,
    sessionmaker,
)

from application.models.http_archive_page import (
    PreparedHTTPArchivePage,
)
from infrastructure.persistence.models.normalized_http_archive import (
    HTTPArchivePageModel,
)


class SqlAlchemyHTTPArchivePageStore:
    """
    Persistance batch/idempotente des pages HTTP Archive.
    """

    def __init__(
        self,
        *,
        session_factory: sessionmaker[Session],
    ) -> None:
        self._session_factory = (
            session_factory
        )

    def persist_batch(
        self,
        records: Sequence[
            PreparedHTTPArchivePage
        ],
    ) -> int:
        submitted = tuple(
            records
        )

        if not submitted:
            return 0

        values = [
            {
                "canonical_value": (
                    record.canonical_value
                ),
                "value_hash": (
                    record.value_hash
                ),
                "hostname": (
                    record.hostname
                ),
                "registered_domain": (
                    record.registered_domain
                ),
                "canonicalization_version": (
                    record.canonicalization_version
                ),
                "source_rank": (
                    record.source_rank
                ),
                "source_snapshot": (
                    record.source_snapshot
                ),
                "observed_at": (
                    record.observed_at
                ),
            }
            for record in submitted
        ]

        with self._session_factory() as session:
            with session.begin():
                inserted = (
                    session.execute(
                        pg_insert(
                            HTTPArchivePageModel
                        )
                        .values(
                            values
                        )
                        .on_conflict_do_nothing(
                            index_elements=[
                                "source_snapshot",
                                "canonicalization_version",
                                "value_hash",
                            ]
                        )
                        .returning(
                            HTTPArchivePageModel.id
                        )
                    )
                    .scalars()
                    .all()
                )

        return len(
            inserted
        )