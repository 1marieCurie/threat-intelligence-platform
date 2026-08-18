from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Protocol
from uuid import UUID

from application.ports.outbound.machine_vulnerability_processing_read_repository import (
    MachineVulnerabilityProcessingReadRepository,
    VulnerabilityExposureProcessingState,
)
from application.services.alert_evaluation_service import (
    ExposureAlertTransition,
)
from domain._asset_validation import (
    normalize_datetime_utc,
    validate_uuid,
)
from domain.software_component import (
    SoftwareComponent,
)


class ProcessMachineVulnerabilitiesError(
    RuntimeError
):
    """
    Erreur applicative contrôlée du pipeline
    de traitement des vulnérabilités machine.
    """


class VulnerabilityExposureReconciler(
    Protocol
):
    def reconcile(
        self,
        *,
        organization_id: UUID,
        machine_id: UUID,
        components: tuple[
            SoftwareComponent,
            ...,
        ],
        evaluated_at: datetime,
    ) -> object:
        ...


class VulnerabilityExposureEnricher(
    Protocol
):
    def enrich(
        self,
        *,
        organization_id: UUID,
        machine_id: UUID,
        component_ids: tuple[
            UUID,
            ...,
        ],
    ) -> object:
        ...


class ExposureAlertEvaluator(
    Protocol
):
    def evaluate(
        self,
        *,
        organization_id: UUID,
        machine_id: UUID,
        transitions: tuple[
            ExposureAlertTransition,
            ...,
        ],
        evaluated_at: datetime,
    ) -> object:
        ...


@dataclass(
    frozen=True,
    slots=True,
)
class ProcessMachineVulnerabilitiesResult:
    organization_id: UUID
    machine_id: UUID

    component_count: int
    package_count: int
    application_count: int

    before_exposure_count: int
    after_exposure_count: int

    new_exposure_count: int
    existing_exposure_count: int

    alert_transition_count: int
    alert_evaluation_invoked: bool


class ProcessMachineVulnerabilitiesService:
    """
    Orchestrateur V1 des vulnérabilités d'une machine.

    Pipeline :

        current SoftwareComponent
            ↓
        snapshot BEFORE
            ↓
        package → GitHub Advisory
            ↓
        application → CISA KEV
            ↓
        severity
            ↓
        priority
            ↓
        snapshot AFTER
            ↓
        ExposureAlertTransition
            ↓
        AlertEvaluationService
            ↓
        NotificationPort

    Le service ne connaît :
    - ni SQLAlchemy ;
    - ni PostgreSQL ;
    - ni FastAPI ;
    - ni Gmail.

    Il orchestre uniquement les services applicatifs
    déjà existants.

    Le même pipeline machine pourra être déclenché
    après :
    - un changement d'inventaire ;
    - un changement Threat Intelligence.

    La sélection ciblée des machines impactées par
    un changement Threat Intelligence reste séparée.
    Aucun scheduler n'est introduit ici.
    """

    def __init__(
        self,
        *,
        read_repository: (
            MachineVulnerabilityProcessingReadRepository
        ),
        package_reconciler: (
            VulnerabilityExposureReconciler
        ),
        cisa_kev_reconciler: (
            VulnerabilityExposureReconciler
        ),
        severity_enricher: (
            VulnerabilityExposureEnricher
        ),
        priority_enricher: (
            VulnerabilityExposureEnricher
        ),
        alert_evaluator: (
            ExposureAlertEvaluator
        ),
    ) -> None:
        if read_repository is None:
            raise ValueError(
                "read_repository must not be None"
            )

        if package_reconciler is None:
            raise ValueError(
                "package_reconciler must not be None"
            )

        if cisa_kev_reconciler is None:
            raise ValueError(
                "cisa_kev_reconciler must not be None"
            )

        if severity_enricher is None:
            raise ValueError(
                "severity_enricher must not be None"
            )

        if priority_enricher is None:
            raise ValueError(
                "priority_enricher must not be None"
            )

        if alert_evaluator is None:
            raise ValueError(
                "alert_evaluator must not be None"
            )

        self._read_repository = (
            read_repository
        )

        self._package_reconciler = (
            package_reconciler
        )

        self._cisa_kev_reconciler = (
            cisa_kev_reconciler
        )

        self._severity_enricher = (
            severity_enricher
        )

        self._priority_enricher = (
            priority_enricher
        )

        self._alert_evaluator = (
            alert_evaluator
        )

    def process(
        self,
        *,
        organization_id: UUID,
        machine_id: UUID,
        evaluated_at: datetime,
    ) -> ProcessMachineVulnerabilitiesResult:
        normalized_organization_id = (
            validate_uuid(
                organization_id,
                field_name="organization_id",
            )
        )

        normalized_machine_id = (
            validate_uuid(
                machine_id,
                field_name="machine_id",
            )
        )

        normalized_evaluated_at = (
            normalize_datetime_utc(
                evaluated_at,
                field_name="evaluated_at",
            )
        )

        # =====================================================
        # 1. Inventaire logiciel courant
        # =====================================================

        components = (
            self._read_repository
            .find_machine_components(
                organization_id=(
                    normalized_organization_id
                ),
                machine_id=(
                    normalized_machine_id
                ),
            )
        )

        if not components:
            return (
                ProcessMachineVulnerabilitiesResult(
                    organization_id=(
                        normalized_organization_id
                    ),
                    machine_id=(
                        normalized_machine_id
                    ),
                    component_count=0,
                    package_count=0,
                    application_count=0,
                    before_exposure_count=0,
                    after_exposure_count=0,
                    new_exposure_count=0,
                    existing_exposure_count=0,
                    alert_transition_count=0,
                    alert_evaluation_invoked=False,
                )
            )

        component_ids = tuple(
            component.id
            for component in components
        )

        packages = tuple(
            component
            for component in components
            if (
                component.component_type
                == "package"
            )
        )

        applications = tuple(
            component
            for component in components
            if (
                component.component_type
                == "application"
            )
        )

        if (
            len(packages)
            + len(applications)
            != len(components)
        ):
            raise (
                ProcessMachineVulnerabilitiesError(
                    "Unsupported software "
                    "component type"
                )
            )

        # =====================================================
        # 2. Snapshot BEFORE
        # =====================================================

        before_states = (
            self._read_repository
            .find_exposure_states(
                organization_id=(
                    normalized_organization_id
                ),
                machine_id=(
                    normalized_machine_id
                ),
                component_ids=(
                    component_ids
                ),
            )
        )

        before_by_id = self._index_states(
            before_states,
            snapshot_name="before",
        )

        # =====================================================
        # 3. Package → GitHub Advisory
        # =====================================================

        if packages:
            self._package_reconciler.reconcile(
                organization_id=(
                    normalized_organization_id
                ),
                machine_id=(
                    normalized_machine_id
                ),
                components=packages,
                evaluated_at=(
                    normalized_evaluated_at
                ),
            )

        # =====================================================
        # 4. Application → CISA KEV
        # =====================================================

        if applications:
            self._cisa_kev_reconciler.reconcile(
                organization_id=(
                    normalized_organization_id
                ),
                machine_id=(
                    normalized_machine_id
                ),
                components=applications,
                evaluated_at=(
                    normalized_evaluated_at
                ),
            )

        # =====================================================
        # 5. Severity
        # =====================================================

        self._severity_enricher.enrich(
            organization_id=(
                normalized_organization_id
            ),
            machine_id=(
                normalized_machine_id
            ),
            component_ids=(
                component_ids
            ),
        )

        # =====================================================
        # 6. Priority
        # =====================================================

        self._priority_enricher.enrich(
            organization_id=(
                normalized_organization_id
            ),
            machine_id=(
                normalized_machine_id
            ),
            component_ids=(
                component_ids
            ),
        )

        # =====================================================
        # 7. Snapshot AFTER
        # =====================================================

        after_states = (
            self._read_repository
            .find_exposure_states(
                organization_id=(
                    normalized_organization_id
                ),
                machine_id=(
                    normalized_machine_id
                ),
                component_ids=(
                    component_ids
                ),
            )
        )

        after_by_id = self._index_states(
            after_states,
            snapshot_name="after",
        )

        # =====================================================
        # 8. BEFORE → AFTER
        # =====================================================

        transitions = (
            self._build_alert_transitions(
                before_by_id=before_by_id,
                after_by_id=after_by_id,
            )
        )

        new_exposure_count = sum(
            1
            for transition in transitions
            if transition.is_new_exposure
        )

        existing_exposure_count = (
            len(transitions)
            - new_exposure_count
        )

        # =====================================================
        # 9. Alerts + NotificationPort
        # =====================================================

        alert_evaluation_invoked = False

        if transitions:
            self._alert_evaluator.evaluate(
                organization_id=(
                    normalized_organization_id
                ),
                machine_id=(
                    normalized_machine_id
                ),
                transitions=transitions,
                evaluated_at=(
                    normalized_evaluated_at
                ),
            )

            alert_evaluation_invoked = True

        # =====================================================
        # Résultat
        # =====================================================

        return (
            ProcessMachineVulnerabilitiesResult(
                organization_id=(
                    normalized_organization_id
                ),
                machine_id=(
                    normalized_machine_id
                ),
                component_count=len(
                    components
                ),
                package_count=len(
                    packages
                ),
                application_count=len(
                    applications
                ),
                before_exposure_count=len(
                    before_states
                ),
                after_exposure_count=len(
                    after_states
                ),
                new_exposure_count=(
                    new_exposure_count
                ),
                existing_exposure_count=(
                    existing_exposure_count
                ),
                alert_transition_count=len(
                    transitions
                ),
                alert_evaluation_invoked=(
                    alert_evaluation_invoked
                ),
            )
        )

    @staticmethod
    def _index_states(
        states: tuple[
            VulnerabilityExposureProcessingState,
            ...,
        ],
        *,
        snapshot_name: str,
    ) -> dict[
        UUID,
        VulnerabilityExposureProcessingState,
    ]:
        indexed: dict[
            UUID,
            VulnerabilityExposureProcessingState,
        ] = {}

        for state in states:
            if state.exposure_id in indexed:
                raise (
                    ProcessMachineVulnerabilitiesError(
                        "Duplicate exposure id in "
                        f"{snapshot_name} snapshot"
                    )
                )

            indexed[
                state.exposure_id
            ] = state

        return indexed

    @classmethod
    def _build_alert_transitions(
        cls,
        *,
        before_by_id: dict[
            UUID,
            VulnerabilityExposureProcessingState,
        ],
        after_by_id: dict[
            UUID,
            VulnerabilityExposureProcessingState,
        ],
    ) -> tuple[
        ExposureAlertTransition,
        ...,
    ]:
        transitions: list[
            ExposureAlertTransition
        ] = []

        for exposure_id in sorted(
            after_by_id,
            key=str,
        ):
            current = after_by_id[
                exposure_id
            ]

            previous = before_by_id.get(
                exposure_id
            )

            if previous is None:
                transitions.append(
                    ExposureAlertTransition(
                        exposure_id=(
                            current.exposure_id
                        ),
                        canonical_vulnerability_id=(
                            current
                            .canonical_vulnerability_id
                        ),
                        applicability_status=(
                            current
                            .applicability_status
                        ),
                        is_new_exposure=True,
                        previous_priority=None,
                        current_priority=(
                            current.priority
                        ), # pyright: ignore[reportArgumentType]
                        previous_is_kev=False,
                        current_is_kev=(
                            current.is_kev
                        ),
                    )
                )

                continue

            cls._validate_stable_identity(
                previous=previous,
                current=current,
            )

            transitions.append(
                ExposureAlertTransition(
                    exposure_id=(
                        current.exposure_id
                    ),
                    canonical_vulnerability_id=(
                        current
                        .canonical_vulnerability_id
                    ),
                    applicability_status=(
                        current
                        .applicability_status
                    ),
                    is_new_exposure=False,
                    previous_priority=(
                        previous.priority
                    ),
                    current_priority=(
                        current.priority
                    ), # pyright: ignore[reportArgumentType]
                    previous_is_kev=(
                        previous.is_kev
                    ),
                    current_is_kev=(
                        current.is_kev
                    ),
                )
            )

        return tuple(
            transitions
        )

    @staticmethod
    def _validate_stable_identity(
        *,
        previous: (
            VulnerabilityExposureProcessingState
        ),
        current: (
            VulnerabilityExposureProcessingState
        ),
    ) -> None:
        if (
            previous.software_component_id
            != current.software_component_id
        ):
            raise (
                ProcessMachineVulnerabilitiesError(
                    "Exposure software component "
                    "identity changed during processing"
                )
            )

        if (
            previous.canonical_vulnerability_id
            != current.canonical_vulnerability_id
        ):
            raise (
                ProcessMachineVulnerabilitiesError(
                    "Exposure canonical vulnerability "
                    "identity changed during processing"
                )
            )