from __future__ import annotations

import os
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from infrastructure.persistence.models.assets import (
    MachineModel,
    OrganizationModel,
    SoftwareComponentModel,
    VulnerabilityExposureModel,
)


DEMO_DETECTED_BY = "final_demo_scenario"


def find_demo_exposure(
    factory: sessionmaker[Session],
    hostname: str,
) -> tuple[VulnerabilityExposureModel, UUID]:
    slug = os.getenv("TIP_DEMO_ORGANIZATION_SLUG", "").strip().lower()
    if not slug:
        raise RuntimeError("TIP_DEMO_ORGANIZATION_SLUG is not defined")

    with factory() as session:
        organization_id = session.scalar(
            select(OrganizationModel.id)
            .where(
                func.lower(OrganizationModel.slug) == slug,
                OrganizationModel.is_active.is_(True),
            )
            .limit(1)
        )
        if organization_id is None:
            raise RuntimeError(
                f"No active organization found for TIP_DEMO_ORGANIZATION_SLUG={slug}"
            )

        row = session.execute(
            select(VulnerabilityExposureModel, MachineModel.id)
            .join(
                SoftwareComponentModel,
                VulnerabilityExposureModel.software_component_id
                == SoftwareComponentModel.id,
            )
            .join(
                MachineModel,
                SoftwareComponentModel.machine_id == MachineModel.id,
            )
            .where(
                MachineModel.organization_id == organization_id,
                MachineModel.hostname == hostname,
                SoftwareComponentModel.detected_by == DEMO_DETECTED_BY,
            )
            .limit(1)
        ).first()

        if row is None:
            raise RuntimeError(
                f"Demo exposure for {hostname} not found in organization {slug}. "
                "Run 'prepare' first."
            )

        exposure = row[0]
        machine_id = row[1]
        session.expunge(exposure)
        return exposure, machine_id
