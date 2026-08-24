from __future__ import annotations

import os
from dataclasses import dataclass

from sqlalchemy import Engine

from application.services.reevaluate_threat_intelligence_targets_service import (
    ReevaluateThreatIntelligenceTargetsService,
)
from application.services.threat_intelligence_scheduler_cycle_service import (
    ThreatIntelligenceSchedulerCycleService,
)
from infrastructure.bootstrap.cisa_kev_canonical_correlation import (
    build_cisa_kev_canonical_correlation_job,
)
from infrastructure.bootstrap.cisa_kev_ingestion import (
    build_cisa_kev_ingestion_job,
)
from infrastructure.bootstrap.cisa_kev_normalization import (
    build_cisa_kev_normalization_job,
)
from infrastructure.bootstrap.epss_canonical_correlation import (
    build_epss_canonical_correlation_job,
)
from infrastructure.bootstrap.epss_synchronization import (
    build_epss_synchronization_job,
)
from infrastructure.bootstrap.github_advisory_canonical_correlation import (
    build_github_advisory_canonical_correlation_job,
)
from infrastructure.bootstrap.github_advisory_ingestion import (
    build_github_advisory_ingestion_job,
)
from infrastructure.bootstrap.github_advisory_normalization import (
    build_github_advisory_normalization_job,
)
from infrastructure.bootstrap.machine_vulnerability_processing import (
    build_process_machine_vulnerabilities_service,
)
from infrastructure.notifications.notification_adapter_factory import (
    load_notification_port,
)
from infrastructure.persistence.sqlalchemy.asset_engine import (
    create_asset_engine,
)
from infrastructure.persistence.sqlalchemy.engine import (
    create_ingestion_engine,
)
from infrastructure.persistence.sqlalchemy.readers.relevant_exposure_cve_reader import (
    SqlAlchemyRelevantExposureCVEReader,
)
from infrastructure.persistence.sqlalchemy.readers.scheduler_source_resolver import (
    SqlAlchemySchedulerSourceResolver,
)
from infrastructure.persistence.sqlalchemy.readers.threat_intelligence_reprocessing_target_repository import (
    SqlAlchemyThreatIntelligenceReprocessingTargetRepository,
)
from infrastructure.persistence.sqlalchemy.session import (
    create_session_factory,
)
from infrastructure.scheduler.refresh_stages import (
    CisaKevRefreshStage,
    EPSSRefreshStage,
    GitHubAdvisoryRefreshStage,
)


CISA_KEV_SOURCE_CODE = (
    "CISA_KEV"
)

GITHUB_ADVISORY_SOURCE_CODE = (
    "GITHUB_ADVISORY"
)


GITHUB_MAX_PAGES_ENV = (
    "TIP_SCHEDULER_GITHUB_MAX_PAGES"
)

GITHUB_CYCLE_PAGE_BUDGET_ENV = (
    "TIP_SCHEDULER_GITHUB_CYCLE_PAGE_BUDGET"
)

EPSS_BATCH_SIZE_ENV = (
    "TIP_SCHEDULER_EPSS_BATCH_SIZE"
)

EPSS_MAX_BATCHES_ENV = (
    "TIP_SCHEDULER_EPSS_MAX_BATCHES"
)


DEFAULT_GITHUB_MAX_PAGES = 100

DEFAULT_GITHUB_CYCLE_PAGE_BUDGET = 5

DEFAULT_EPSS_BATCH_SIZE = 500
DEFAULT_EPSS_MAX_BATCHES = 10_000


@dataclass(
    frozen=True,
    slots=True,
)
class ThreatIntelligenceSchedulerRuntime:
    cycle_service: (
        ThreatIntelligenceSchedulerCycleService
    )

    lock_engine: Engine


def build_threat_intelligence_scheduler_runtime(
) -> ThreatIntelligenceSchedulerRuntime:
    github_max_pages = (
        _read_bounded_positive_integer(
            variable_name=(
                GITHUB_MAX_PAGES_ENV
            ),
            default=(
                DEFAULT_GITHUB_MAX_PAGES
            ),
            maximum=500,
        )
    )

    github_cycle_page_budget = (
        _read_bounded_positive_integer(
            variable_name=(
                GITHUB_CYCLE_PAGE_BUDGET_ENV
            ),
            default=(
                DEFAULT_GITHUB_CYCLE_PAGE_BUDGET
            ),
            maximum=(
                github_max_pages
            ),
        )
    )

    epss_batch_size = (
        _read_bounded_positive_integer(
            variable_name=(
                EPSS_BATCH_SIZE_ENV
            ),
            default=(
                DEFAULT_EPSS_BATCH_SIZE
            ),
            maximum=(
                EPSSRefreshStage
                .MAX_BATCH_SIZE
            ),
        )
    )

    epss_max_batches = (
        _read_bounded_positive_integer(
            variable_name=(
                EPSS_MAX_BATCHES_ENV
            ),
            default=(
                DEFAULT_EPSS_MAX_BATCHES
            ),
            maximum=100_000,
        )
    )

    ingestion_engine = (
        create_ingestion_engine()
    )

    ingestion_session_factory = (
        create_session_factory(
            ingestion_engine
        )
    )

    asset_engine = (
        create_asset_engine()
    )

    asset_session_factory = (
        create_session_factory(
            asset_engine
        )
    )

    source_resolver = (
        SqlAlchemySchedulerSourceResolver(
            session_factory=(
                ingestion_session_factory
            )
        )
    )

    cisa_source_id = (
        source_resolver
        .resolve_enabled_source_id(
            CISA_KEV_SOURCE_CODE
        )
    )

    github_source_id = (
        source_resolver
        .resolve_enabled_source_id(
            GITHUB_ADVISORY_SOURCE_CODE
        )
    )

    cisa_stage = (
        CisaKevRefreshStage(
            ingestion_job=(
                build_cisa_kev_ingestion_job(
                    source_id=(
                        cisa_source_id
                    )
                )
            ),
            normalization_job=(
                build_cisa_kev_normalization_job(
                    source_id=(
                        cisa_source_id
                    )
                )
            ),
            canonical_job=(
                build_cisa_kev_canonical_correlation_job()
            ),
        )
    )

    github_stage = (
        GitHubAdvisoryRefreshStage(
            ingestion_job=(
                build_github_advisory_ingestion_job(
                    source_id=(
                        github_source_id
                    )
                )
            ),
            normalization_job=(
                build_github_advisory_normalization_job(
                    source_id=(
                        github_source_id
                    )
                )
            ),
            canonical_job=(
                build_github_advisory_canonical_correlation_job(
                    incremental_only=True
                )
            ),
            max_pages=(
                github_max_pages
            ),
            cycle_page_budget=(
                github_cycle_page_budget
            ),
        )
    )

    relevant_cve_reader = (
        SqlAlchemyRelevantExposureCVEReader(
            session_factory=(
                asset_session_factory
            )
        )
    )

    epss_stage = (
        EPSSRefreshStage(
            cve_reader=(
                relevant_cve_reader
            ),
            synchronization_job=(
                build_epss_synchronization_job()
            ),
            canonical_job=(
                build_epss_canonical_correlation_job()
            ),
            batch_size=(
                epss_batch_size
            ),
            max_batches=(
                epss_max_batches
            ),
        )
    )

    notification_port = (
        load_notification_port()
    )

    machine_processor = (
        build_process_machine_vulnerabilities_service(
            session_factory=(
                asset_session_factory
            ),
            notification_port=(
                notification_port
            ),
            cisa_kev_source_code=(
                CISA_KEV_SOURCE_CODE
            ),
        )
    )

    target_repository = (
        SqlAlchemyThreatIntelligenceReprocessingTargetRepository(
            session_factory=(
                asset_session_factory
            )
        )
    )

    target_reevaluator = (
        ReevaluateThreatIntelligenceTargetsService(
            target_repository=(
                target_repository
            ),
            machine_processor=(
                machine_processor
            ),
        )
    )

    cycle_service = (
        ThreatIntelligenceSchedulerCycleService(
            cisa_kev_stage=(
                cisa_stage
            ),
            github_advisory_stage=(
                github_stage
            ),
            epss_stage=(
                epss_stage
            ),
            target_reevaluator=(
                target_reevaluator
            ),
        )
    )

    return (
        ThreatIntelligenceSchedulerRuntime(
            cycle_service=(
                cycle_service
            ),
            lock_engine=(
                asset_engine
            ),
        )
    )


def _read_bounded_positive_integer(
    *,
    variable_name: str,
    default: int,
    maximum: int,
) -> int:
    if (
        isinstance(
            default,
            bool,
        )
        or not isinstance(
            default,
            int,
        )
        or default < 1
    ):
        raise ValueError(
            "default must be a positive integer"
        )

    if (
        isinstance(
            maximum,
            bool,
        )
        or not isinstance(
            maximum,
            int,
        )
        or maximum < 1
    ):
        raise ValueError(
            "maximum must be "
            "a positive integer"
        )

    if default > maximum:
        raise ValueError(
            "default must not exceed maximum"
        )

    raw_value = (
        os.environ.get(
            variable_name
        )
    )

    if raw_value is None:
        return default

    normalized = (
        raw_value.strip()
    )

    if not normalized:
        raise RuntimeError(
            f"{variable_name} "
            "must not be empty"
        )

    try:
        value = int(
            normalized
        )

    except ValueError as error:
        raise RuntimeError(
            f"{variable_name} "
            "must be an integer"
        ) from error

    if value < 1:
        raise RuntimeError(
            f"{variable_name} "
            "must be greater than zero"
        )

    if value > maximum:
        raise RuntimeError(
            f"{variable_name} "
            f"must not exceed {maximum}"
        )

    return value