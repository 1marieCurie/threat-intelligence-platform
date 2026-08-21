from __future__ import annotations

from uuid import UUID

from sqlalchemy import (
    and_,
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

from application.models.dashboard import (
    DashboardLatestAlert,
    DashboardMetrics,
    DashboardPriorityDistribution,
    DashboardTopMachine,
)
from application.ports.outbound.dashboard_read_repository import (
    DashboardReadRepository,
    DashboardReadRepositoryError,
)
from infrastructure.persistence.models.assets import (
    AlertModel,
    MachineModel,
    SoftwareComponentModel,
    VulnerabilityExposureModel,
)


class SqlAlchemyDashboardReadRepository(
    DashboardReadRepository
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

    def read_metrics(
        self,
        *,
        organization_id: UUID,
    ) -> DashboardMetrics:
        if not isinstance(
            organization_id,
            UUID,
        ):
            raise TypeError(
                "organization_id must be UUID"
            )

        try:
            with (
                self._session_factory()
                as session
            ):
                machine_count = (
                    session.scalar(
                        select(
                            func.count(
                                MachineModel.id
                            )
                        )
                        .where(
                            MachineModel
                            .organization_id
                            == organization_id
                        )
                    )
                    or 0
                )

                component_count = (
                    session.scalar(
                        select(
                            func.count(
                                SoftwareComponentModel
                                .id
                            )
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
                        .where(
                            MachineModel
                            .organization_id
                            == organization_id
                        )
                    )
                    or 0
                )

                exposure_row = (
                    session.execute(
                        self._build_exposure_statement(
                            organization_id
                        )
                    )
                    .one()
                )

                alert_row = (
                    session.execute(
                        self._build_alert_statement(
                            organization_id
                        )
                    )
                    .one()
                )

                top_machines = (
                    self._read_top_machines(
                        session=session,
                        organization_id=(
                            organization_id
                        ),
                    )
                )

                latest_alerts = (
                    self._read_latest_alerts(
                        session=session,
                        organization_id=(
                            organization_id
                        ),
                    )
                )

        except SQLAlchemyError as error:
            raise (
                DashboardReadRepositoryError(
                    "Unable to read "
                    "dashboard metrics"
                )
            ) from error

        return DashboardMetrics(
            machine_count=int(
                machine_count
            ),
            component_count=int(
                component_count
            ),
            confirmed_exposure_count=int(
                exposure_row[0] or 0
            ),
            potential_exposure_count=int(
                exposure_row[1] or 0
            ),
            critical_exposure_count=int(
                exposure_row[2] or 0
            ),
            kev_exposure_count=int(
                exposure_row[3] or 0
            ),
            pending_alert_count=int(
                alert_row[0] or 0
            ),
            failed_alert_count=int(
                alert_row[1] or 0
            ),
            critical_confirmed_exposure_count=int(
                exposure_row[4] or 0
            ),
            confirmed_kev_exposure_count=int(
                exposure_row[5] or 0
            ),
            priority_distribution=(
                DashboardPriorityDistribution(
                    low=int(
                        exposure_row[6]
                        or 0
                    ),
                    medium=int(
                        exposure_row[7]
                        or 0
                    ),
                    high=int(
                        exposure_row[8]
                        or 0
                    ),
                    critical=int(
                        exposure_row[9]
                        or 0
                    ),
                )
            ),
            top_machines=top_machines,
            latest_alerts=latest_alerts,
        )

    @staticmethod
    def _build_exposure_statement(
        organization_id: UUID,
    ):
        exposure_id = (
            VulnerabilityExposureModel.id
        )

        return (
            select(
                func.count(
                    exposure_id
                ).filter(
                    VulnerabilityExposureModel
                    .applicability_status
                    == "confirmed"
                ),
                func.count(
                    exposure_id
                ).filter(
                    VulnerabilityExposureModel
                    .applicability_status
                    == "potential"
                ),
                func.count(
                    exposure_id
                ).filter(
                    VulnerabilityExposureModel
                    .priority
                    == "CRITICAL"
                ),
                func.count(
                    exposure_id
                ).filter(
                    VulnerabilityExposureModel
                    .is_kev
                    .is_(True)
                ),
                func.count(
                    exposure_id
                ).filter(
                    and_(
                        VulnerabilityExposureModel
                        .applicability_status
                        == "confirmed",
                        VulnerabilityExposureModel
                        .priority
                        == "CRITICAL",
                    )
                ),
                func.count(
                    exposure_id
                ).filter(
                    and_(
                        VulnerabilityExposureModel
                        .applicability_status
                        == "confirmed",
                        VulnerabilityExposureModel
                        .is_kev
                        .is_(True),
                    )
                ),
                func.count(
                    exposure_id
                ).filter(
                    VulnerabilityExposureModel
                    .priority
                    == "LOW"
                ),
                func.count(
                    exposure_id
                ).filter(
                    VulnerabilityExposureModel
                    .priority
                    == "MEDIUM"
                ),
                func.count(
                    exposure_id
                ).filter(
                    VulnerabilityExposureModel
                    .priority
                    == "HIGH"
                ),
                func.count(
                    exposure_id
                ).filter(
                    VulnerabilityExposureModel
                    .priority
                    == "CRITICAL"
                ),
            )
            .select_from(
                VulnerabilityExposureModel
            )
            .join(
                SoftwareComponentModel,
                SoftwareComponentModel.id
                == VulnerabilityExposureModel
                .software_component_id,
            )
            .join(
                MachineModel,
                MachineModel.id
                == SoftwareComponentModel
                .machine_id,
            )
            .where(
                MachineModel.organization_id
                == organization_id
            )
        )

    @staticmethod
    def _build_alert_statement(
        organization_id: UUID,
    ):
        return (
            select(
                func.count(
                    AlertModel.id
                ).filter(
                    AlertModel.status
                    == "pending"
                ),
                func.count(
                    AlertModel.id
                ).filter(
                    AlertModel.status
                    == "failed"
                ),
            )
            .where(
                AlertModel.organization_id
                == organization_id
            )
        )

    @staticmethod
    def _read_top_machines(
        *,
        session: Session,
        organization_id: UUID,
    ) -> tuple[
        DashboardTopMachine,
        ...,
    ]:
        exposure_count = (
            func.count(
                VulnerabilityExposureModel.id
            )
            .label(
                "exposure_count"
            )
        )

        critical_count = (
            func.count(
                VulnerabilityExposureModel.id
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
                VulnerabilityExposureModel.id
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
                exposure_count,
                critical_count,
                kev_count,
            )
            .select_from(
                MachineModel
            )
            .join(
                SoftwareComponentModel,
                SoftwareComponentModel
                .machine_id
                == MachineModel.id,
            )
            .join(
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
            )
            .order_by(
                exposure_count.desc(),
                MachineModel.hostname.asc(),
            )
            .limit(5)
        )

        rows = (
            session.execute(
                statement
            )
            .tuples()
            .all()
        )

        return tuple(
            DashboardTopMachine(
                machine_id=row[0],
                hostname=row[1],
                exposure_count=int(
                    row[2] or 0
                ),
                critical_count=int(
                    row[3] or 0
                ),
                kev_count=int(
                    row[4] or 0
                ),
            )
            for row in rows
        )

    @staticmethod
    def _read_latest_alerts(
        *,
        session: Session,
        organization_id: UUID,
    ) -> tuple[
        DashboardLatestAlert,
        ...,
    ]:
        statement = (
            select(
                AlertModel.id,
                AlertModel.alert_type,
                AlertModel.status,
                AlertModel.created_at,
                AlertModel.sent_at,
                MachineModel.id,
                MachineModel.hostname,
                VulnerabilityExposureModel
                .priority,
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
            .where(
                AlertModel.organization_id
                == organization_id
            )
            .order_by(
                AlertModel.created_at.desc()
            )
            .limit(5)
        )

        rows = (
            session.execute(
                statement
            )
            .tuples()
            .all()
        )

        return tuple(
            DashboardLatestAlert(
                alert_id=row[0],
                alert_type=row[1],
                status=row[2],  # pyright: ignore[reportArgumentType]
                created_at=row[3],
                sent_at=row[4],
                machine_id=row[5],
                hostname=row[6],
                priority=row[7],  # pyright: ignore[reportArgumentType]
            )
            for row in rows
        )