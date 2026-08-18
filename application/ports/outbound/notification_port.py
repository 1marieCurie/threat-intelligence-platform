from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol
from uuid import UUID


@dataclass(
    frozen=True,
    slots=True,
)
class AlertNotification:
    alert_id: UUID

    organization_id: UUID
    machine_id: UUID

    vulnerability_exposure_id: UUID
    canonical_vulnerability_id: UUID

    alert_type: str

    recipient_user_id: UUID
    recipient_email: str
    recipient_display_name: str


class NotificationDeliveryError(
    RuntimeError
):
    """
    Erreur contrôlée provenant d'un adapter
    de notification.
    """


class NotificationPort(
    Protocol
):
    def send(
        self,
        notification: AlertNotification,
    ) -> None:
        ...