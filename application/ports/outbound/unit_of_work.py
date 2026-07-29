from __future__ import annotations

from types import TracebackType
from typing import Protocol, Self

from application.ports.outbound.cisa_kev_vulnerability_repository import (
    CisaKevVulnerabilityRepository,
)
from application.ports.outbound.github_advisory_vulnerability_repository import (
    GitHubAdvisoryVulnerabilityRepository,
)
from application.ports.outbound.ingestion_run_repository import (
    IngestionRunRepository,
)
from application.ports.outbound.raw_payload_repository import (
    RawPayloadRepository,
)
from application.ports.outbound.sync_state_repository import (
    SyncStateRepository,
)


class UnitOfWork(Protocol):
    ingestion_runs: IngestionRunRepository
    raw_payloads: RawPayloadRepository
    sync_states: SyncStateRepository

    cisa_kev_vulnerabilities: (
        CisaKevVulnerabilityRepository
    )

    github_advisory_vulnerabilities: (
        GitHubAdvisoryVulnerabilityRepository
    )

    def __enter__(self) -> Self:
        ...

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        ...

    def commit(self) -> None:
        ...

    def rollback(self) -> None:
        ...