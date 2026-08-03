from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Protocol
from uuid import UUID


@dataclass(
    frozen=True,
    slots=True,
)
class URLhausBlacklistData:
    name: str
    status: str


@dataclass(
    frozen=True,
    slots=True,
)
class URLhausURLData:
    raw_payload_id: UUID
    urlhaus_id: int
    malicious_url: str
    hostname: str
    normalizer_version: str

    urlhaus_reference: str | None = None
    url_status: str | None = None
    date_added: datetime | None = None
    threat_type: str | None = None
    reporter: str | None = None
    larted: bool | None = None

    tags: tuple[str, ...] = ()

    blacklists: tuple[
        URLhausBlacklistData,
        ...,
    ] = ()


class URLhausURLRepository(
    Protocol
):
    def save(
        self,
        url_record: URLhausURLData,
    ) -> UUID:
        """
        Persiste un enregistrement URLhaus normalisé.
        """
        ...

    def exists_by_raw_payload_id(
        self,
        raw_payload_id: UUID,
    ) -> bool:
        """
        Vérifie si un payload brut a déjà été normalisé.
        """
        ...