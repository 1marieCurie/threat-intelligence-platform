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
    
@dataclass(
    frozen=True,
    slots=True,
)
class MachineComponentView:
    component_id: UUID
    component_type: str

    name: str
    version: str | None
    vendor: str | None

    ecosystem: str | None
    scope: str | None

    detected_by: str


@dataclass(
    frozen=True,
    slots=True,
)
class MachineExposureView:
    exposure_id: UUID
    canonical_vulnerability_id: UUID

    primary_identifier: str | None

    component_id: UUID
    component_name: str
    component_version: str | None

    applicability_status: str

    severity: str | None
    priority: str | None

    is_kev: bool

    match_rule: str
    match_version: str | None


@dataclass(
    frozen=True,
    slots=True,
)
class MachineDetail:
    machine_id: UUID
    machine_uid: UUID

    hostname: str

    os_name: str
    os_version: str
    architecture: str

    last_inventory_at: datetime | None

    components: tuple[
        MachineComponentView,
        ...,
    ]

    exposures: tuple[
        MachineExposureView,
        ...,
    ]