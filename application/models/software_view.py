from __future__ import annotations

from dataclasses import dataclass


@dataclass(
    frozen=True,
    slots=True,
)
class SoftwareSummary:
    component_type: str

    name: str

    version: str | None

    vendor: str | None
    ecosystem: str | None

    machine_count: int
    exposure_count: int