from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Protocol
from uuid import UUID

from domain.alert import Alert

@dataclass(
    frozen=True,
    slots=True,
)
class AlertSentUpdate:
    alert_id: UUID
    sent_at: datetime

@dataclass(
    frozen=True,
    slots=True,
)
class PendingAlertCreate:
    organization_id: UUID
    machine_id: UUID
    vulnerability_exposure_id: UUID
    canonical_vulnerability_id: UUID
    alert_type: str
    recipient_user_id: UUID
    deduplication_key: str
    created_at: datetime


class AlertRepository(
    Protocol
):
    def insert_pending_many(
        self,
        *,
        alerts: tuple[
            PendingAlertCreate,
            ...,
        ],
    ) -> tuple[
        Alert,
        ...,
    ]:
        """
        Persiste uniquement les nouvelles alertes.

        Une deduplication_key déjà existante pour
        l'organisation doit être ignorée.
        """
        ...
        
    def mark_sent_many(
        self,
        *,
        organization_id: UUID,
        updates: tuple[
            AlertSentUpdate,
            ...,
        ],
    ) -> int:
        ...


    def mark_failed_many(
        self,
        *,
        organization_id: UUID,
        alert_ids: tuple[
            UUID,
            ...,
        ],
    ) -> int:
        ...