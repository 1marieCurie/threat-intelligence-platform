from __future__ import annotations

from collections.abc import Callable

from sqlalchemy import (
    select,
)
from sqlalchemy.exc import (
    SQLAlchemyError,
)
from sqlalchemy.orm import (
    Session,
)

from application.ports.outbound.threat_intelligence_reprocessing_target_repository import (
    ThreatIntelligenceReprocessingTarget,
    ThreatIntelligenceReprocessingTargetRepositoryError,
)
from infrastructure.persistence.models.assets import (
    MachineModel,
    OrganizationModel,
    SoftwareComponentModel,
    VulnerabilityExposureModel,
)


SessionFactory = Callable[
    [],
    Session,
]


class SqlAlchemyThreatIntelligenceReprocessingTargetRepository:
    """
    Sélection globale des machines à réévaluer après
    un changement Threat Intelligence.

    Ce repository ne fait aucun matching de vulnérabilité.

    Il sélectionne uniquement des couples :

        organization_id + machine_id

    afin de conserver explicitement la frontière tenant.
    """

    def __init__(
        self,
        *,
        session_factory: SessionFactory,
    ) -> None:
        if session_factory is None:
            raise ValueError(
                "session_factory must not be None"
            )

        if not callable(
            session_factory
        ):
            raise TypeError(
                "session_factory must be callable"
            )

        self._session_factory = (
            session_factory
        )

    def find_application_targets(
        self,
    ) -> tuple[
        ThreatIntelligenceReprocessingTarget,
        ...,
    ]:
        return self._find_component_targets(
            component_type="application",
        )

    def find_package_targets(
        self,
    ) -> tuple[
        ThreatIntelligenceReprocessingTarget,
        ...,
    ]:
        return self._find_component_targets(
            component_type="package",
        )

    def find_exposure_targets(
        self,
    ) -> tuple[
        ThreatIntelligenceReprocessingTarget,
        ...,
    ]:
        statement = (
            select(
                MachineModel.organization_id,
                MachineModel.id,
            )
            .select_from(
                MachineModel
            )
            .join(
                OrganizationModel,
                OrganizationModel.id
                == MachineModel.organization_id,
            )
            .join(
                SoftwareComponentModel,
                SoftwareComponentModel.machine_id
                == MachineModel.id,
            )
            .join(
                VulnerabilityExposureModel,
                (
                    VulnerabilityExposureModel
                    .software_component_id
                    == SoftwareComponentModel.id
                ),
            )
            .where(
                OrganizationModel.is_active.is_(
                    True
                )
            )
            .distinct()
            .order_by(
                MachineModel.organization_id.asc(),
                MachineModel.id.asc(),
            )
        )

        return self._execute(
            statement=statement,
            error_message=(
                "Unable to select exposure "
                "reprocessing targets"
            ),
        )

    def _find_component_targets(
        self,
        *,
        component_type: str,
    ) -> tuple[
        ThreatIntelligenceReprocessingTarget,
        ...,
    ]:
        if component_type not in {
            "application",
            "package",
        }:
            raise ValueError(
                "Unsupported component type"
            )

        statement = (
            select(
                MachineModel.organization_id,
                MachineModel.id,
            )
            .select_from(
                MachineModel
            )
            .join(
                OrganizationModel,
                OrganizationModel.id
                == MachineModel.organization_id,
            )
            .join(
                SoftwareComponentModel,
                SoftwareComponentModel.machine_id
                == MachineModel.id,
            )
            .where(
                OrganizationModel.is_active.is_(
                    True
                ),
                (
                    SoftwareComponentModel
                    .component_type
                    == component_type
                ),
            )
            .distinct()
            .order_by(
                MachineModel.organization_id.asc(),
                MachineModel.id.asc(),
            )
        )

        return self._execute(
            statement=statement,
            error_message=(
                "Unable to select "
                f"{component_type} "
                "reprocessing targets"
            ),
        )

    def _execute(
        self,
        *,
        statement,
        error_message: str,
    ) -> tuple[
        ThreatIntelligenceReprocessingTarget,
        ...,
    ]:
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
                ThreatIntelligenceReprocessingTargetRepositoryError(
                    error_message
                )
            ) from error

        return tuple(
            ThreatIntelligenceReprocessingTarget(
                organization_id=(
                    organization_id
                ),
                machine_id=machine_id,
            )
            for (
                organization_id,
                machine_id,
            )
            in rows
        )