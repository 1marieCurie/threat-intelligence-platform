from __future__ import annotations

from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from application.ports.outbound.urlhaus_url_repository import (
    URLhausBlacklistData,
    URLhausURLData,
)
from infrastructure.persistence.models.normalized_urlhaus import (
    URLhausURLModel,
)


class SqlAlchemyURLhausURLRepository:
    """
    Repository SQLAlchemy des observations URLhaus normalisées.

    Les commits restent sous la responsabilité de l'Unit of Work.
    """

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

    def save(
        self,
        url_record: URLhausURLData,
    ) -> UUID:
        if not isinstance(
            url_record,
            URLhausURLData,
        ):
            raise TypeError(
                "url_record must be "
                "a URLhausURLData"
            )

        normalized_id = uuid4()

        model = URLhausURLModel(
            id=normalized_id,
            raw_payload_id=(
                url_record.raw_payload_id
            ),
            urlhaus_id=(
                url_record.urlhaus_id
            ),
            malicious_url=(
                url_record.malicious_url
            ),
            hostname=url_record.hostname,
            urlhaus_reference=(
                url_record.urlhaus_reference
            ),
            url_status=(
                url_record.url_status
            ),
            date_added=(
                url_record.date_added
            ),
            threat_type=(
                url_record.threat_type
            ),
            reporter=url_record.reporter,
            larted=url_record.larted,
            tags=list(
                url_record.tags
            ),
            blacklists=(
                self._serialize_blacklists(
                    url_record.blacklists
                )
            ),
            normalizer_version=(
                url_record.normalizer_version
            ),
        )

        self._session.add(
            model
        )

        self._session.flush()

        return normalized_id

    def exists_by_raw_payload_id(
        self,
        raw_payload_id: UUID,
    ) -> bool:
        if not isinstance(
            raw_payload_id,
            UUID,
        ):
            raise TypeError(
                "raw_payload_id must be a UUID"
            )

        statement = (
            select(
                URLhausURLModel.id
            )
            .where(
                URLhausURLModel.raw_payload_id
                == raw_payload_id
            )
            .limit(1)
        )

        existing_id = (
            self._session
            .execute(statement)
            .scalar_one_or_none()
        )

        return existing_id is not None

    @staticmethod
    def _serialize_blacklists(
        blacklists: tuple[
            URLhausBlacklistData,
            ...,
        ],
    ) -> list[dict[str, str]]:
        return [
            {
                "name": blacklist.name,
                "status": blacklist.status,
            }
            for blacklist in blacklists
        ]