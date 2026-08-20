from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID


@dataclass(
    frozen=True,
    slots=True,
)
class AlertSummary:
    alert_id: UUID

    alert_type: str
    status: str

    created_at: datetime
    sent_at: datetime | None

    machine_id: UUID
    machine_hostname: str

    canonical_vulnerability_id: UUID
    primary_identifier: str | None

    component_name: str | None
    component_version: str | None

    current_priority: str | None
    is_kev: bool | None