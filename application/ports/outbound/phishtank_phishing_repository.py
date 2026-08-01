from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Protocol
from uuid import UUID


@dataclass(
    frozen=True,
    slots=True,
)
class PhishTankNetworkDetailData:
    ip_address: str | None = None
    cidr_block: str | None = None
    announcing_network: str | None = None
    rir: str | None = None
    country: str | None = None
    detail_time: datetime | None = None


@dataclass(
    frozen=True,
    slots=True,
)
class PhishTankPhishingData:
    raw_payload_id: UUID
    phish_id: int
    phishing_url: str
    hostname: str
    normalizer_version: str

    phish_detail_url: str | None = None
    submission_time: datetime | None = None
    verification_time: datetime | None = None
    verified: bool | None = None
    online: bool | None = None
    target: str | None = None

    network_details: tuple[
        PhishTankNetworkDetailData,
        ...,
    ] = ()


class PhishTankPhishingRepository(
    Protocol
):
    def save(
        self,
        phishing: PhishTankPhishingData,
    ) -> UUID:
        """
        Persiste un enregistrement PhishTank normalisé.
        """
        ...

    def exists_by_raw_payload_id(
        self,
        raw_payload_id: UUID,
    ) -> bool:
        """
        Vérifie si le payload brut a déjà été normalisé.
        """
        ...