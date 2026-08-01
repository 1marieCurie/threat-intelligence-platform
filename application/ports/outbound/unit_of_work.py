from __future__ import annotations

from types import TracebackType
from typing import Protocol, Self

from application.ports.outbound.cisa_kev_vulnerability_repository import (
    CisaKevVulnerabilityRepository,
)
from application.ports.outbound.cwe_reference_repository import (
    VulnerabilityCWEReferenceRepository,
)
from application.ports.outbound.cwe_repository import (
    WritableCWERepository,
)
from application.ports.outbound.epss_score_repository import (
    WritableEPSSScoreRepository,
)
from application.ports.outbound.github_advisory_vulnerability_repository import (
    GitHubAdvisoryVulnerabilityRepository,
)
from application.ports.outbound.ingestion_run_payload_repository import (
    IngestionRunPayloadRepository,
)
from application.ports.outbound.ingestion_run_repository import (
    IngestionRunRepository,
)
from application.ports.outbound.phishtank_phishing_repository import (
    PhishTankPhishingRepository,
)
from application.ports.outbound.raw_payload_repository import (
    RawPayloadRepository,
)
from application.ports.outbound.sync_state_repository import (
    SyncStateRepository,
)


class UnitOfWork(Protocol):
    """
    Contrat transactionnel partagé par les services applicatifs.

    Tous les repositories sont injectés par l'implémentation
    concrète de l'Unit of Work.
    """

    ingestion_runs: IngestionRunRepository
    raw_payloads: RawPayloadRepository

    ingestion_run_payloads: (
        IngestionRunPayloadRepository
    )

    sync_states: SyncStateRepository

    cisa_kev_vulnerabilities: (
        CisaKevVulnerabilityRepository
    )

    github_advisory_vulnerabilities: (
        GitHubAdvisoryVulnerabilityRepository
    )

    phishtank_phishing: (
        PhishTankPhishingRepository
    )

    cwe_weaknesses: WritableCWERepository

    vulnerability_cwe_references: (
        VulnerabilityCWEReferenceRepository
    )

    epss_scores: WritableEPSSScoreRepository

    def __enter__(
        self,
    ) -> Self:
        ...

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        ...

    def commit(
        self,
    ) -> None:
        ...

    def rollback(
        self,
    ) -> None:
        ...