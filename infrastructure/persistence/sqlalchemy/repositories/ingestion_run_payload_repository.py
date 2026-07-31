from __future__ import annotations

from datetime import UTC, datetime
from typing import Sequence
from uuid import UUID

from sqlalchemy.dialects.postgresql import (
    insert as postgresql_insert,
)
from sqlalchemy.orm import Session

from application.ports.outbound.ingestion_run_payload_repository import (
    IngestionRunPayloadBatchResult,
    IngestionRunPayloadLink,
)
from infrastructure.persistence.models.raw import (
    IngestionRunPayloadModel,
)


class SqlAlchemyIngestionRunPayloadRepository:
    """
    Repository PostgreSQL des observations de payloads.

    Les associations sont écrites en une seule requête
    INSERT ... ON CONFLICT DO NOTHING par lot.
    """

    def __init__(
        self,
        session: Session,
    ) -> None:
        if not isinstance(
            session,
            Session,
        ):
            raise TypeError(
                "session must be a SQLAlchemy Session"
            )

        self._session = session

    def link_many_ignore_existing(
        self,
        links: Sequence[
            IngestionRunPayloadLink
        ],
    ) -> IngestionRunPayloadBatchResult:
        if isinstance(
            links,
            (str, bytes),
        ):
            raise TypeError(
                "links must be a sequence of "
                "IngestionRunPayloadLink"
            )

        try:
            submitted_links = tuple(
                links
            )
        except TypeError as error:
            raise TypeError(
                "links must be a sequence of "
                "IngestionRunPayloadLink"
            ) from error

        submitted_count = len(
            submitted_links
        )

        if submitted_count == 0:
            return IngestionRunPayloadBatchResult(
                submitted_count=0,
                unique_count=0,
                inserted_count=0,
            )

        links_by_identity: dict[
            tuple[UUID, UUID],
            IngestionRunPayloadLink,
        ] = {}

        for link in submitted_links:
            self._validate_link(
                link
            )

            identity = (
                link.ingestion_run_id,
                link.raw_payload_id,
            )

            links_by_identity.setdefault(
                identity,
                link,
            )

        observed_at_fallback = datetime.now(
            UTC
        )

        values = [
            {
                "ingestion_run_id": (
                    link.ingestion_run_id
                ),
                "raw_payload_id": (
                    link.raw_payload_id
                ),
                "observed_at": (
                    link.observed_at
                    or observed_at_fallback
                ),
            }
            for link in links_by_identity.values()
        ]

        statement = (
            postgresql_insert(
                IngestionRunPayloadModel
            )
            .values(
                values
            )
            .on_conflict_do_nothing(
                index_elements=[
                    (
                        IngestionRunPayloadModel
                        .ingestion_run_id
                    ),
                    (
                        IngestionRunPayloadModel
                        .raw_payload_id
                    ),
                ]
            )
            .returning(
                (
                    IngestionRunPayloadModel
                    .ingestion_run_id
                ),
                (
                    IngestionRunPayloadModel
                    .raw_payload_id
                ),
            )
        )

        inserted_rows = tuple(
            self._session
            .execute(
                statement
            )
            .all()
        )

        return IngestionRunPayloadBatchResult(
            submitted_count=(
                submitted_count
            ),
            unique_count=len(
                links_by_identity
            ),
            inserted_count=len(
                inserted_rows
            ),
        )

    @classmethod
    def _validate_link(
        cls,
        link: IngestionRunPayloadLink,
    ) -> None:
        if not isinstance(
            link,
            IngestionRunPayloadLink,
        ):
            raise TypeError(
                "Every link must be an "
                "IngestionRunPayloadLink instance"
            )

        cls._validate_uuid(
            link.ingestion_run_id,
            field_name="ingestion_run_id",
        )

        cls._validate_uuid(
            link.raw_payload_id,
            field_name="raw_payload_id",
        )

        if (
            link.observed_at is not None
            and (
                not isinstance(
                    link.observed_at,
                    datetime,
                )
                or link.observed_at.tzinfo
                is None
                or link.observed_at.utcoffset()
                is None
            )
        ):
            raise ValueError(
                "observed_at must be a "
                "timezone-aware datetime or None"
            )

    @staticmethod
    def _validate_uuid(
        value: UUID,
        *,
        field_name: str,
    ) -> None:
        if not isinstance(
            value,
            UUID,
        ):
            raise TypeError(
                f"{field_name} must be a UUID"
            )