from __future__ import annotations

from types import TracebackType
from typing import Self

from sqlalchemy.orm import Session, sessionmaker

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
from infrastructure.persistence.sqlalchemy.repositories.cisa_kev_vulnerability_repository import (
    SqlAlchemyCisaKevVulnerabilityRepository,
)
from infrastructure.persistence.sqlalchemy.repositories.github_advisory_vulnerability_repository import (
    SqlAlchemyGitHubAdvisoryVulnerabilityRepository,
)
from infrastructure.persistence.sqlalchemy.repositories.ingestion_run_repository import (
    SqlAlchemyIngestionRunRepository,
)
from infrastructure.persistence.sqlalchemy.repositories.raw_payload_repository import (
    SqlAlchemyRawPayloadRepository,
)
from infrastructure.persistence.sqlalchemy.repositories.sync_state_repository import (
    SqlAlchemySyncStateRepository,
)
from application.ports.outbound.cwe_repository import (
    WritableCWERepository,
)
from infrastructure.persistence.sqlalchemy.repositories.cwe_repository import (
    SqlAlchemyCWERepository,
)
from application.ports.outbound.cwe_reference_repository import (
    VulnerabilityCWEReferenceRepository,
)
from infrastructure.persistence.sqlalchemy.repositories.cwe_reference_repository import (
    SqlAlchemyVulnerabilityCWEReferenceRepository,
)


class SqlAlchemyUnitOfWork:
    def __init__(
        self,
        session_factory: sessionmaker[Session],
    ) -> None:
        if session_factory is None:
            raise ValueError(
                "session_factory must not be None"
            )

        self._session_factory = (
            session_factory
        )

        self._session: Session | None = None

        self.ingestion_runs: (
            IngestionRunRepository
        )

        self.raw_payloads: (
            RawPayloadRepository
        )

        self.sync_states: (
            SyncStateRepository
        )

        self.cisa_kev_vulnerabilities: (
            CisaKevVulnerabilityRepository
        )

        self.github_advisory_vulnerabilities: (
            GitHubAdvisoryVulnerabilityRepository
        )
        
        self.cwe_weaknesses: (
            WritableCWERepository
        )

    def __enter__(self) -> Self:
        if self._session is not None:
            raise RuntimeError(
                "Unit of Work is already active"
            )

        self._session = (
            self._session_factory()
        )

        self.ingestion_runs = (
            SqlAlchemyIngestionRunRepository(
                session=self._session,
            )
        )

        self.raw_payloads = (
            SqlAlchemyRawPayloadRepository(
                session=self._session,
            )
        )

        self.sync_states = (
            SqlAlchemySyncStateRepository(
                session=self._session,
            )
        )

        self.cisa_kev_vulnerabilities = (
            SqlAlchemyCisaKevVulnerabilityRepository(
                session=self._session,
            )
        )

        self.github_advisory_vulnerabilities = (
            SqlAlchemyGitHubAdvisoryVulnerabilityRepository(
                session=self._session,
            )
        )
        
        self.cwe_weaknesses = (
            SqlAlchemyCWERepository(
                session=self._session,
            )
        )
        
        self.vulnerability_cwe_references = (
            SqlAlchemyVulnerabilityCWEReferenceRepository(
                session=self._session,
            )
        )

        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        try:
            if exc_type is not None:
                self.rollback()

            elif self._session is not None:
                # Aucune transaction implicite ne doit
                # rester ouverte lorsque commit() a été
                # oublié par le service appelant.
                self.rollback()

        finally:
            if self._session is not None:
                self._session.close()
                self._session = None

    def commit(self) -> None:
        session = self._require_session()
        session.commit()

    def rollback(self) -> None:
        session = self._require_session()
        session.rollback()

    def _require_session(self) -> Session:
        if self._session is None:
            raise RuntimeError(
                "Unit of Work is not active"
            )

        return self._session