from __future__ import annotations

from uuid import UUID

from sqlalchemy import (
    and_,
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
    MachineComponentView,
    MachineDetail,
    MachineExposureView,
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
from infrastructure.persistence.models.canonical import (
    CanonicalVulnerabilityIdentifierModel,
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

    # =========================================================
    # Liste des machines
    # =========================================================

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

    # =========================================================
    # Détail machine
    # =========================================================

    def get_machine_detail(
        self,
        *,
        organization_id: UUID,
        machine_id: UUID,
    ) -> MachineDetail | None:
        if not isinstance(
            organization_id,
            UUID,
        ):
            raise TypeError(
                "organization_id must be UUID"
            )

        if not isinstance(
            machine_id,
            UUID,
        ):
            raise TypeError(
                "machine_id must be UUID"
            )

        try:
            with (
                self._session_factory()
                as session
            ):
                # ---------------------------------------------
                # Machine
                # ---------------------------------------------

                machine_row = (
                    session.execute(
                        select(
                            MachineModel.id,
                            MachineModel.machine_uid,
                            MachineModel.hostname,
                            MachineModel.os_name,
                            MachineModel.os_version,
                            MachineModel.architecture,
                            MachineModel.last_inventory_at,
                        )
                        .where(
                            MachineModel
                            .organization_id
                            == organization_id,
                            MachineModel.id
                            == machine_id,
                        )
                    )
                    .tuples()
                    .one_or_none()
                )

                if machine_row is None:
                    return None

                # ---------------------------------------------
                # Composants
                # ---------------------------------------------

                component_rows = (
                    session.execute(
                        select(
                            SoftwareComponentModel.id,
                            SoftwareComponentModel
                            .component_type,
                            SoftwareComponentModel.name,
                            SoftwareComponentModel.version,
                            SoftwareComponentModel.vendor,
                            SoftwareComponentModel.ecosystem,
                            SoftwareComponentModel.scope,
                            SoftwareComponentModel
                            .detected_by,
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
                            == organization_id,
                            MachineModel.id
                            == machine_id,
                        )
                        .order_by(
                            SoftwareComponentModel
                            .name
                            .asc(),
                            SoftwareComponentModel
                            .id
                            .asc(),
                        )
                    )
                    .tuples()
                    .all()
                )

                # ---------------------------------------------
                # Expositions
                #
                # On rattache l'identifiant primaire
                # CVE/GHSA lorsqu'il existe.
                # ---------------------------------------------

                exposure_rows = (
                    session.execute(
                        select(
                            VulnerabilityExposureModel.id,
                            VulnerabilityExposureModel
                            .canonical_vulnerability_id,
                            CanonicalVulnerabilityIdentifierModel
                            .value,
                            SoftwareComponentModel.id,
                            SoftwareComponentModel.name,
                            SoftwareComponentModel.version,
                            VulnerabilityExposureModel
                            .applicability_status,
                            VulnerabilityExposureModel
                            .severity,
                            VulnerabilityExposureModel
                            .priority,
                            VulnerabilityExposureModel
                            .is_kev,
                            VulnerabilityExposureModel
                            .match_rule,
                            VulnerabilityExposureModel
                            .match_version,
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
                        .outerjoin(
                            CanonicalVulnerabilityIdentifierModel,
                            and_(
                                CanonicalVulnerabilityIdentifierModel
                                .vulnerability_id
                                == VulnerabilityExposureModel
                                .canonical_vulnerability_id,
                                CanonicalVulnerabilityIdentifierModel
                                .is_primary
                                .is_(True),
                            ),
                        )
                        .where(
                            MachineModel
                            .organization_id
                            == organization_id,
                            MachineModel.id
                            == machine_id,
                        )
                        .order_by(
                            VulnerabilityExposureModel
                            .priority
                            .desc()
                            .nullslast(),
                            SoftwareComponentModel
                            .name
                            .asc(),
                            VulnerabilityExposureModel
                            .id
                            .asc(),
                        )
                    )
                    .tuples()
                    .all()
                )

        except SQLAlchemyError as error:
            raise (
                MachineReadRepositoryError(
                    "Unable to read "
                    "machine detail"
                )
            ) from error

        components = tuple(
            MachineComponentView(
                component_id=row[0],
                component_type=row[1],
                name=row[2],
                version=row[3],
                vendor=row[4],
                ecosystem=row[5],
                scope=row[6],
                detected_by=row[7],
            )
            for row in component_rows
        )

        exposures = tuple(
            MachineExposureView(
                exposure_id=row[0],
                canonical_vulnerability_id=(
                    row[1]
                ),
                primary_identifier=row[2],
                component_id=row[3],
                component_name=row[4],
                component_version=row[5],
                applicability_status=row[6],
                severity=row[7],
                priority=row[8],
                is_kev=bool(
                    row[9]
                ),
                match_rule=row[10],
                match_version=row[11],
            )
            for row in exposure_rows
        )

        return MachineDetail(
            machine_id=machine_row[0],
            machine_uid=machine_row[1],
            hostname=machine_row[2],
            os_name=machine_row[3],
            os_version=machine_row[4],
            architecture=machine_row[5],
            last_inventory_at=machine_row[6],
            components=components,
            exposures=exposures,
        )