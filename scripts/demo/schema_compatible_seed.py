from __future__ import annotations

from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy.orm import Session

from infrastructure.persistence.models.assets import (
    MachineModel,
    SoftwareComponentModel,
    VulnerabilityExposureModel,
)


DEMO_COMPONENT_NAME = "Apache Log4j 2 (log4j-core)"
DEMO_NORMALIZED_NAME = "apache log4j 2 log4j core"
DEMO_VENDOR = "Apache Software Foundation"
DEMO_NORMALIZED_VENDOR = "apache software foundation"
DEMO_DETECTED_BY = "final_demo_scenario"


def seed_machine_and_exposure(
    session: Session,
    *,
    organization_id: UUID,
    canonical_id: UUID,
    hostname: str,
    applicability: str,
    priority: str,
    version: str | None,
    now: datetime,
) -> tuple[UUID, UUID]:
    """Create demo data while respecting SoftwareComponent V1 constraints.

    Inventory V1 models packages only for PyPI/npm. Log4j is a Maven
    artifact, so the controlled PFA demo represents it as an installed
    application instead of widening the production schema just for a demo.

    The CVE, affected version and vulnerability exposure remain real; only
    the inventory representation is adapted to the capabilities of V1.
    """

    machine_id = uuid4()
    component_id = uuid4()
    exposure_id = uuid4()

    session.add(
        MachineModel(
            id=machine_id,
            organization_id=organization_id,
            machine_uid=uuid4(),
            hostname=hostname,
            os_name="Windows",
            os_version="11 Pro",
            architecture="x86_64",
            last_inventory_at=now,
            created_at=now,
            updated_at=now,
        )
    )
    session.flush()

    session.add(
        SoftwareComponentModel(
            id=component_id,
            machine_id=machine_id,
            component_type="application",
            name=DEMO_COMPONENT_NAME,
            normalized_name=DEMO_NORMALIZED_NAME,
            version=version,
            vendor=DEMO_VENDOR,
            normalized_vendor=DEMO_NORMALIZED_VENDOR,
            ecosystem=None,
            external_id=(
                "demo://windows/application/"
                f"{hostname.lower()}/log4j-core"
            ),
            scope=None,
            detected_by=DEMO_DETECTED_BY,
            created_at=now,
            updated_at=now,
        )
    )
    session.flush()

    session.add(
        VulnerabilityExposureModel(
            id=exposure_id,
            software_component_id=component_id,
            canonical_vulnerability_id=canonical_id,
            applicability_status=applicability,
            match_rule=(
                "demo_exact_version_match"
                if applicability == "confirmed"
                else "demo_missing_version_match"
            ),
            match_version="1.0.0",
            severity="CRITICAL",
            priority=priority,
            is_kev=False,
            first_detected_at=now,
            last_evaluated_at=now,
        )
    )

    return machine_id, exposure_id
