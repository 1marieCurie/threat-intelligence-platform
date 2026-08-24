from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Protocol
from uuid import UUID

from application.ports.outbound.threat_intelligence_reprocessing_target_repository import (
    ThreatIntelligenceReprocessingTarget,
    ThreatIntelligenceReprocessingTargetRepository,
)
from application.services.process_machine_vulnerabilities_service import (
    ProcessMachineVulnerabilitiesResult,
)
from domain._asset_validation import (
    normalize_datetime_utc,
    validate_uuid,
)


class MachineVulnerabilityProcessor(
    Protocol
):
    def process(
        self,
        *,
        organization_id: UUID,
        machine_id: UUID,
        evaluated_at: datetime,
    ) -> ProcessMachineVulnerabilitiesResult:
        ...


@dataclass(
    frozen=True,
    slots=True,
)
class ReevaluateThreatIntelligenceTargetsResult:
    cisa_kev_changed: bool
    github_advisory_changed: bool
    epss_changed: bool

    selected_target_count: int
    processed_target_count: int

    alert_transition_count: int
    alert_evaluation_invoked_count: int


class ReevaluateThreatIntelligenceTargetsService:
    """
    Réévalue les machines susceptibles d'être affectées
    par une évolution des données Threat Intelligence.

    Ce service NE contient aucune logique de détection.

    Sélection V1 :

    CISA KEV changé
        -> machines avec applications
        -> machines ayant déjà des expositions

    GitHub Advisory changé
        -> machines avec packages

    EPSS changé
        -> machines ayant déjà des expositions

    Pourquoi inclure les expositions lors d'un changement
    CISA KEV ?

    Un package peut déjà être exposé via GitHub Advisory
    et sa CanonicalVulnerability peut ensuite entrer dans
    CISA KEV.

    Dans ce cas :

        aucun nouvel inventaire
            ↓
        même exposition
            ↓
        is_kev False -> True
            ↓
        nouvelle priority éventuelle
            ↓
        AlertEvaluationService

    La responsabilité du recalcul reste entièrement dans
    ProcessMachineVulnerabilitiesService.
    """

    def __init__(
        self,
        *,
        target_repository: (
            ThreatIntelligenceReprocessingTargetRepository
        ),
        machine_processor: MachineVulnerabilityProcessor,
    ) -> None:
        if target_repository is None:
            raise ValueError(
                "target_repository must not be None"
            )

        if machine_processor is None:
            raise ValueError(
                "machine_processor must not be None"
            )

        self._target_repository = (
            target_repository
        )

        self._machine_processor = (
            machine_processor
        )

    def reevaluate(
        self,
        *,
        cisa_kev_changed: bool,
        github_advisory_changed: bool,
        epss_changed: bool,
        evaluated_at: datetime,
    ) -> (
        ReevaluateThreatIntelligenceTargetsResult
    ):
        self._validate_bool(
            cisa_kev_changed,
            field_name="cisa_kev_changed",
        )

        self._validate_bool(
            github_advisory_changed,
            field_name=(
                "github_advisory_changed"
            ),
        )

        self._validate_bool(
            epss_changed,
            field_name="epss_changed",
        )

        normalized_evaluated_at = (
            normalize_datetime_utc(
                evaluated_at,
                field_name="evaluated_at",
            )
        )

        if not (
            cisa_kev_changed
            or github_advisory_changed
            or epss_changed
        ):
            return (
                ReevaluateThreatIntelligenceTargetsResult(
                    cisa_kev_changed=False,
                    github_advisory_changed=False,
                    epss_changed=False,
                    selected_target_count=0,
                    processed_target_count=0,
                    alert_transition_count=0,
                    alert_evaluation_invoked_count=0,
                )
            )

        targets: dict[
            tuple[
                UUID,
                UUID,
            ],
            ThreatIntelligenceReprocessingTarget,
        ] = {}

        if cisa_kev_changed:
            self._add_targets(
                destination=targets,
                values=(
                    self._target_repository
                    .find_application_targets()
                ),
            )

            self._add_targets(
                destination=targets,
                values=(
                    self._target_repository
                    .find_exposure_targets()
                ),
            )

        if github_advisory_changed:
            self._add_targets(
                destination=targets,
                values=(
                    self._target_repository
                    .find_package_targets()
                ),
            )

        if epss_changed:
            self._add_targets(
                destination=targets,
                values=(
                    self._target_repository
                    .find_exposure_targets()
                ),
            )

        ordered_targets = tuple(
            targets[key]
            for key in sorted(
                targets,
                key=lambda value: (
                    str(value[0]),
                    str(value[1]),
                ),
            )
        )

        processed_target_count = 0
        alert_transition_count = 0
        alert_evaluation_invoked_count = 0

        for target in ordered_targets:
            result = (
                self._machine_processor.process(
                    organization_id=(
                        target.organization_id
                    ),
                    machine_id=(
                        target.machine_id
                    ),
                    evaluated_at=(
                        normalized_evaluated_at
                    ),
                )
            )

            processed_target_count += 1

            alert_transition_count += (
                result.alert_transition_count
            )

            if (
                result.alert_evaluation_invoked
            ):
                (
                    alert_evaluation_invoked_count
                ) += 1

        return (
            ReevaluateThreatIntelligenceTargetsResult(
                cisa_kev_changed=(
                    cisa_kev_changed
                ),
                github_advisory_changed=(
                    github_advisory_changed
                ),
                epss_changed=epss_changed,
                selected_target_count=len(
                    ordered_targets
                ),
                processed_target_count=(
                    processed_target_count
                ),
                alert_transition_count=(
                    alert_transition_count
                ),
                alert_evaluation_invoked_count=(
                    alert_evaluation_invoked_count
                ),
            )
        )

    @staticmethod
    def _add_targets(
        *,
        destination: dict[
            tuple[
                UUID,
                UUID,
            ],
            ThreatIntelligenceReprocessingTarget,
        ],
        values: tuple[
            ThreatIntelligenceReprocessingTarget,
            ...,
        ],
    ) -> None:
        if not isinstance(
            values,
            tuple,
        ):
            raise TypeError(
                "target repository results "
                "must be tuples"
            )

        for target in values:
            if not isinstance(
                target,
                ThreatIntelligenceReprocessingTarget,
            ):
                raise TypeError(
                    "target repository returned "
                    "an invalid target"
                )

            organization_id = (
                validate_uuid(
                    target.organization_id,
                    field_name=(
                        "organization_id"
                    ),
                )
            )

            machine_id = validate_uuid(
                target.machine_id,
                field_name="machine_id",
            )

            normalized_target = (
                ThreatIntelligenceReprocessingTarget(
                    organization_id=(
                        organization_id
                    ),
                    machine_id=machine_id,
                )
            )

            destination[
                (
                    organization_id,
                    machine_id,
                )
            ] = normalized_target

    @staticmethod
    def _validate_bool(
        value: bool,
        *,
        field_name: str,
    ) -> None:
        if not isinstance(
            value,
            bool,
        ):
            raise TypeError(
                f"{field_name} must be a boolean"
            )