from __future__ import annotations

from uuid import UUID

from sqlalchemy import (
    distinct,
    func,
    select,
)
from sqlalchemy.exc import (
    SQLAlchemyError,
)
from sqlalchemy.orm import (
    Session,
    sessionmaker,
)

from application.models.machine_view import (
    MachineSummary,
)
from application.ports.outbound.machine_read_repository import (
    MachineReadRepository,
    MachineReadRepositoryError,
)
from infrastructure.persistence.models.assets import (
    MachineModel,
    SoftwareComponentModel,
    VulnerabilityExposureModel,
)


class SqlAlchemyMachineReadRepository(
    MachineReadRepository
):
    def __init__(
        self,
        session_factory: (
            sessionmaker[Session]
        ),
    ) -> None:
        if session_factory is None:
            raise ValueError(
                "session_factory must not be None"
            )

        self._session_factory = (
            session_factory
        )

    def list_machines(
        self,
        *,
        organization_id: UUID,
    ) -> tuple[
        MachineSummary,
        ...,
    ]:
        if not isinstance(
            organization_id,
            UUID,
        ):
            raise TypeError(
                "organization_id must be UUID"
            )

        component_count = (
            func.count(
                distinct(
                    SoftwareComponentModel.id
                )
            )
            .label(
                "component_count"
            )
        )

        exposure_count = (
            func.count(
                distinct(
                    VulnerabilityExposureModel.id
                )
            )
            .label(
                "exposure_count"
            )
        )

        critical_count = (
            func.count(
                distinct(
                    VulnerabilityExposureModel.id
                )
            )
            .filter(
                VulnerabilityExposureModel
                .priority
                == "CRITICAL"
            )
            .label(
                "critical_count"
            )
        )

        kev_count = (
            func.count(
                distinct(
                    VulnerabilityExposureModel.id
                )
            )
            .filter(
                VulnerabilityExposureModel
                .is_kev
                .is_(True)
            )
            .label(
                "kev_count"
            )
        )

        statement = (
            select(
                MachineModel.id,
                MachineModel.hostname,
                MachineModel.os_name,
                MachineModel.os_version,
                MachineModel.architecture,
                MachineModel.last_inventory_at,
                component_count,
                exposure_count,
                critical_count,
                kev_count,
            )
            .select_from(
                MachineModel
            )
            .outerjoin(
                SoftwareComponentModel,
                SoftwareComponentModel
                .machine_id
                == MachineModel.id,
            )
            .outerjoin(
                VulnerabilityExposureModel,
                VulnerabilityExposureModel
                .software_component_id
                == SoftwareComponentModel.id,
            )
            .where(
                MachineModel.organization_id
                == organization_id
            )
            .group_by(
                MachineModel.id,
                MachineModel.hostname,
                MachineModel.os_name,
                MachineModel.os_version,
                MachineModel.architecture,
                MachineModel.last_inventory_at,
            )
            .order_by(
                MachineModel.hostname.asc(),
                MachineModel.id.asc(),
            )
        )

        try:
            with (
                self._session_factory()
                as session
            ):
                rows = (
                    session.execute(
                        statement
                    )
                    .tuples()
                    .all()
                )

        except SQLAlchemyError as error:
            raise (
                MachineReadRepositoryError(
                    "Unable to read machines"
                )
            ) from error

        return tuple(
            MachineSummary(
                machine_id=row[0],
                hostname=row[1],
                os_name=row[2],
                os_version=row[3],
                architecture=row[4],
                last_inventory_at=row[5],
                component_count=int(
                    row[6] or 0
                ),
                exposure_count=int(
                    row[7] or 0
                ),
                critical_exposure_count=int(
                    row[8] or 0
                ),
                kev_exposure_count=int(
                    row[9] or 0
                ),
            )
            for row in rows
        )