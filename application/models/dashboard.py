from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Literal
from uuid import UUID


DashboardPriority = Literal[
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL",
]

DashboardAlertStatus = Literal[
    "pending",
    "sent",
    "failed",
]

DashboardActionKind = Literal[
    "critical_confirmed",
    "confirmed_kev",
    "notification_attention",
]


@dataclass(
    frozen=True,
    slots=True,
)
class DashboardPriorityDistribution:
    low: int
    medium: int
    high: int
    critical: int


@dataclass(
    frozen=True,
    slots=True,
)
class DashboardTopMachine:
    machine_id: UUID
    hostname: str
    exposure_count: int
    critical_count: int
    kev_count: int


@dataclass(
    frozen=True,
    slots=True,
)
class DashboardLatestAlert:
    alert_id: UUID
    alert_type: str
    status: DashboardAlertStatus
    created_at: datetime
    sent_at: datetime | None
    machine_id: UUID
    hostname: str
    priority: DashboardPriority | None


@dataclass(
    frozen=True,
    slots=True,
)
class DashboardMetrics:
    machine_count: int
    component_count: int

    confirmed_exposure_count: int
    potential_exposure_count: int

    critical_exposure_count: int
    kev_exposure_count: int

    pending_alert_count: int
    failed_alert_count: int

    critical_confirmed_exposure_count: int
    confirmed_kev_exposure_count: int

    priority_distribution: (
        DashboardPriorityDistribution
    )

    top_machines: tuple[
        DashboardTopMachine,
        ...,
    ]

    latest_alerts: tuple[
        DashboardLatestAlert,
        ...,
    ]


@dataclass(
    frozen=True,
    slots=True,
)
class DashboardPriorityAction:
    kind: DashboardActionKind
    title: str
    count: int
    priority: DashboardPriority


@dataclass(
    frozen=True,
    slots=True,
)
class DashboardSummary:
    machine_count: int
    component_count: int

    confirmed_exposure_count: int
    potential_exposure_count: int

    critical_exposure_count: int
    kev_exposure_count: int

    pending_alert_count: int
    failed_alert_count: int

    priority_distribution: (
        DashboardPriorityDistribution
    )

    top_machines: tuple[
        DashboardTopMachine,
        ...,
    ]

    priority_actions: tuple[
        DashboardPriorityAction,
        ...,
    ]

    latest_alerts: tuple[
        DashboardLatestAlert,
        ...,
    ]