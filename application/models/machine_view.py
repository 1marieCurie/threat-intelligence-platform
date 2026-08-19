from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID


@dataclass(
    frozen=True,
    slots=True,
)
class MachineSummary:
    machine_id: UUID
    hostname: str

    os_name: str
    os_version: str
    architecture: str

    last_inventory_at: datetime | None

    component_count: int
    exposure_count: int
    critical_exposure_count: int
    kev_exposure_count: int