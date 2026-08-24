from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol
from uuid import UUID


@dataclass(
    frozen=True,
    slots=True,
)
class ThreatIntelligenceReprocessingTarget:
    """
    Machine devant être réévaluée après un changement
    Threat Intelligence.

    organization_id est toujours conservé avec machine_id
    afin de préserver la frontière multi-tenant.
    """

    organization_id: UUID
    machine_id: UUID


class ThreatIntelligenceReprocessingTargetRepositoryError(
    RuntimeError
):
    pass


class ThreatIntelligenceReprocessingTargetRepository(
    Protocol
):
    """
    Sélectionne uniquement les machines potentiellement
    concernées par une famille de changements.

    Aucune logique de matching CVE/GHSA/KEV ne doit être
    reproduite ici.

    Le véritable matching reste dans :
    - ReconcilePackageVulnerabilityExposuresService ;
    - ReconcileCisaKevApplicationExposuresService ;
    - les enrichisseurs severity / priority ;
    - ProcessMachineVulnerabilitiesService.
    """

    def find_application_targets(
        self,
    ) -> tuple[
        ThreatIntelligenceReprocessingTarget,
        ...,
    ]:
        ...

    def find_package_targets(
        self,
    ) -> tuple[
        ThreatIntelligenceReprocessingTarget,
        ...,
    ]:
        ...

    def find_exposure_targets(
        self,
    ) -> tuple[
        ThreatIntelligenceReprocessingTarget,
        ...,
    ]:
        ...