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

from application.models.software_view import (
    SoftwareSummary,
)
from application.ports.outbound.software_read_repository import (
    SoftwareReadRepository,
    SoftwareReadRepositoryError,
)
from infrastructure.persistence.models.assets import (
    MachineModel,
    SoftwareComponentModel,
    VulnerabilityExposureModel,
)


class SqlAlchemySoftwareReadRepository(
    SoftwareReadRepository
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

    def list_software(
        self,
        *,
        organization_id: UUID,
    ) -> tuple[
        SoftwareSummary,
        ...,
    ]:
        if not isinstance(
            organization_id,
            UUID,
        ):
            raise TypeError(
                "organization_id must be UUID"
            )

        statement = (
            select(
                SoftwareComponentModel
                .component_type,

                SoftwareComponentModel
                .name,

                SoftwareComponentModel
                .version,

                SoftwareComponentModel
                .vendor,

                SoftwareComponentModel
                .ecosystem,

                func.count(
                    distinct(
                        MachineModel.id
                    )
                ).label(
                    "machine_count"
                ),

                func.count(
                    distinct(
                        VulnerabilityExposureModel.id
                    )
                ).label(
                    "exposure_count"
                ),
            )
            .select_from(
                SoftwareComponentModel
            )
            .join(
                MachineModel,
                MachineModel.id
                == SoftwareComponentModel
                .machine_id,
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
                SoftwareComponentModel
                .component_type,

                SoftwareComponentModel
                .name,

                SoftwareComponentModel
                .version,

                SoftwareComponentModel
                .vendor,

                SoftwareComponentModel
                .ecosystem,
            )
            .order_by(
                SoftwareComponentModel
                .name
                .asc(),

                SoftwareComponentModel
                .version
                .asc()
                .nullslast(),
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
                SoftwareReadRepositoryError(
                    "Unable to read software"
                )
            ) from error

        return tuple(
            SoftwareSummary(
                component_type=row[0],
                name=row[1],
                version=row[2],
                vendor=row[3],
                ecosystem=row[4],
                machine_count=int(
                    row[5] or 0
                ),
                exposure_count=int(
                    row[6] or 0
                ),
            )
            for row in rows
        )