from __future__ import annotations

from uuid import UUID

from sqlalchemy import (
    and_,
    select,
)
from sqlalchemy.exc import (
    SQLAlchemyError,
)
from sqlalchemy.orm import (
    Session,
    aliased,
    sessionmaker,
)

from application.models.alert_view import (
    AlertSummary,
)
from application.ports.outbound.alert_read_repository import (
    AlertReadRepository,
    AlertReadRepositoryError,
)
from infrastructure.persistence.models.assets import (
    AlertModel,
    MachineModel,
    SoftwareComponentModel,
    VulnerabilityExposureModel,
)
from infrastructure.persistence.models.canonical import (
    CanonicalVulnerabilityIdentifierModel,
)


class SqlAlchemyAlertReadRepository(
    AlertReadRepository
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

    def list_alerts(
        self,
        *,
        organization_id: UUID,
    ) -> tuple[
        AlertSummary,
        ...,
    ]:
        if not isinstance(
            organization_id,
            UUID,
        ):
            raise TypeError(
                "organization_id must be UUID"
            )

        primary_identifier = aliased(
            CanonicalVulnerabilityIdentifierModel
        )

        statement = (
            select(
                AlertModel.id,

                AlertModel.alert_type,

                AlertModel.status,

                AlertModel.created_at,

                AlertModel.sent_at,

                AlertModel.machine_id,

                MachineModel.hostname,

                AlertModel
                .canonical_vulnerability_id,

                primary_identifier.value,

                SoftwareComponentModel.name,

                SoftwareComponentModel.version,

                VulnerabilityExposureModel
                .priority,

                VulnerabilityExposureModel
                .is_kev,
            )
            .select_from(
                AlertModel
            )
            .join(
                MachineModel,
                and_(
                    MachineModel.id
                    == AlertModel.machine_id,

                    MachineModel.organization_id
                    == AlertModel.organization_id,
                ),
            )
            .outerjoin(
                VulnerabilityExposureModel,
                VulnerabilityExposureModel.id
                == AlertModel
                .vulnerability_exposure_id,
            )
            .outerjoin(
                SoftwareComponentModel,
                SoftwareComponentModel.id
                == VulnerabilityExposureModel
                .software_component_id,
            )
            .outerjoin(
                primary_identifier,
                and_(
                    primary_identifier
                    .vulnerability_id
                    == AlertModel
                    .canonical_vulnerability_id,

                    primary_identifier
                    .is_primary
                    .is_(True),
                ),
            )
            .where(
                AlertModel.organization_id
                == organization_id
            )
            .order_by(
                AlertModel.created_at.desc(),
                AlertModel.id.desc(),
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
                AlertReadRepositoryError(
                    "Unable to read alerts"
                )
            ) from error

        return tuple(
            AlertSummary(
                alert_id=row[0],
                alert_type=row[1],
                status=row[2],
                created_at=row[3],
                sent_at=row[4],
                machine_id=row[5],
                machine_hostname=row[6],
                canonical_vulnerability_id=(
                    row[7]
                ),
                primary_identifier=row[8],
                component_name=row[9],
                component_version=row[10],
                current_priority=row[11],
                is_kev=row[12],
            )
            for row in rows
        )