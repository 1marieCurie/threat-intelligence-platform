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


@dataclass(
    frozen=True,
    slots=True,
)
class AlertIdentifierView:
    namespace: str
    value: str
    is_primary: bool


@dataclass(
    frozen=True,
    slots=True,
)
class AlertWeaknessView:
    cwe_id: str
    name: str
    description: str


@dataclass(
    frozen=True,
    slots=True,
)
class AlertRecipientView:
    user_id: UUID
    email: str
    display_name: str


@dataclass(
    frozen=True,
    slots=True,
)
class AlertMachineView:
    machine_id: UUID

    hostname: str
    os_name: str
    os_version: str
    architecture: str


@dataclass(
    frozen=True,
    slots=True,
)
class AlertComponentView:
    component_id: UUID

    component_type: str
    name: str
    version: str | None

    vendor: str | None
    ecosystem: str | None
    scope: str | None


@dataclass(
    frozen=True,
    slots=True,
)
class AlertExposureView:
    exposure_id: UUID

    applicability_status: str

    severity: str | None
    priority: str | None

    is_kev: bool

    match_rule: str
    match_version: str | None

    first_detected_at: datetime
    last_evaluated_at: datetime


@dataclass(
    frozen=True,
    slots=True,
)
class AlertDetail:
    alert_id: UUID

    alert_type: str
    status: str

    created_at: datetime
    sent_at: datetime | None

    recipient: AlertRecipientView

    machine: AlertMachineView

    canonical_vulnerability_id: UUID
    primary_identifier: str | None

    identifiers: tuple[
        AlertIdentifierView,
        ...,
    ]

    component: AlertComponentView | None
    exposure: AlertExposureView | None

    epss_score: float | None
    epss_percentile: float | None

    cvss_score: float | None
    cvss_version: str | None
    cvss_vector: str | None

    cvss_source_name: str | None
    cvss_source_role: str | None

    weaknesses: tuple[
        AlertWeaknessView,
        ...,
    ]