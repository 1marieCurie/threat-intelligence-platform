from __future__ import annotations

import argparse
import logging
import os
import sys
import time
from datetime import (
    UTC,
    datetime,
)
from pathlib import Path

from dotenv import load_dotenv
from sqlalchemy import text
from sqlalchemy.engine import (
    Connection,
)
from sqlalchemy.exc import (
    SQLAlchemyError,
)

from application.security.sensitive_data_redactor import (
    redact_sensitive_data,
)
from application.services.threat_intelligence_scheduler_cycle_service import (
    STAGE_STATUS_FAILED,
    ThreatIntelligenceRefreshStageResult,
    ThreatIntelligenceSchedulerCycleResult,
)
from infrastructure.bootstrap.threat_intelligence_scheduler import (
    ThreatIntelligenceSchedulerRuntime,
    build_threat_intelligence_scheduler_runtime,
)
from infrastructure.logging.configuration import (
    configure_logging,
)
from infrastructure.scheduler.cycle_reporting import (
    SchedulerCycleReportArtifacts,
    SchedulerDatabaseEvidence,
    record_scheduler_cycle_report,
)


PROJECT_ROOT = (
    Path(__file__)
    .resolve()
    .parents[2]
)

load_dotenv(
    dotenv_path=(
        PROJECT_ROOT / ".env"
    ),
    override=False,
)


logger = logging.getLogger(
    __name__
)


SCHEDULER_INTERVAL_SECONDS_ENV = (
    "TIP_SCHEDULER_INTERVAL_SECONDS"
)

DEFAULT_INTERVAL_SECONDS = (
    24 * 60 * 60
)

MIN_INTERVAL_SECONDS = 60

MAX_INTERVAL_SECONDS = (
    7 * 24 * 60 * 60
)


ADVISORY_LOCK_CLASS_ID = 84_701
ADVISORY_LOCK_OBJECT_ID = 1


RUN_OUTCOME_OK = "ok"
RUN_OUTCOME_PARTIAL = "partial"
RUN_OUTCOME_SKIPPED = "skipped"


def _parse_arguments(
) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Threat Intelligence Platform "
            "scheduler."
        )
    )

    mode = (
        parser.add_mutually_exclusive_group(
            required=True
        )
    )

    mode.add_argument(
        "--once",
        action="store_true",
        help=(
            "Execute one complete scheduler "
            "cycle and exit."
        ),
    )

    mode.add_argument(
        "--loop",
        action="store_true",
        help=(
            "Run scheduler cycles "
            "continuously."
        ),
    )

    parser.add_argument(
        "--interval-seconds",
        type=int,
        default=None,
        help=(
            "Delay between loop cycles. "
            "Only used with --loop."
        ),
    )

    return parser.parse_args()


def _read_interval_seconds(
    argument_value: int | None,
) -> int:
    if argument_value is not None:
        value = argument_value

    else:
        raw_value = os.environ.get(
            SCHEDULER_INTERVAL_SECONDS_ENV
        )

        if raw_value is None:
            value = (
                DEFAULT_INTERVAL_SECONDS
            )

        else:
            normalized = (
                raw_value.strip()
            )

            if not normalized:
                raise RuntimeError(
                    (
                        f"{SCHEDULER_INTERVAL_SECONDS_ENV} "
                        "must not be empty"
                    )
                )

            try:
                value = int(
                    normalized
                )

            except ValueError as error:
                raise RuntimeError(
                    (
                        f"{SCHEDULER_INTERVAL_SECONDS_ENV} "
                        "must be an integer"
                    )
                ) from error

    if (
        isinstance(
            value,
            bool,
        )
        or not isinstance(
            value,
            int,
        )
    ):
        raise TypeError(
            "interval must be an integer"
        )

    if value < MIN_INTERVAL_SECONDS:
        raise ValueError(
            "interval must be at least "
            f"{MIN_INTERVAL_SECONDS} seconds"
        )

    if value > MAX_INTERVAL_SECONDS:
        raise ValueError(
            "interval must not exceed "
            f"{MAX_INTERVAL_SECONDS} seconds"
        )

    return value


def _try_acquire_lock(
    connection: Connection,
) -> bool:
    result = connection.execute(
        text(
            """
            SELECT pg_try_advisory_lock(
                :class_id,
                :object_id
            )
            """
        ),
        {
            "class_id": (
                ADVISORY_LOCK_CLASS_ID
            ),
            "object_id": (
                ADVISORY_LOCK_OBJECT_ID
            ),
        },
    )

    acquired = (
        result.scalar_one()
    )

    if not isinstance(
        acquired,
        bool,
    ):
        raise RuntimeError(
            "PostgreSQL returned an "
            "invalid advisory lock result"
        )

    return acquired


def _release_lock(
    connection: Connection,
) -> None:
    try:
        result = connection.execute(
            text(
                """
                SELECT pg_advisory_unlock(
                    :class_id,
                    :object_id
                )
                """
            ),
            {
                "class_id": (
                    ADVISORY_LOCK_CLASS_ID
                ),
                "object_id": (
                    ADVISORY_LOCK_OBJECT_ID
                ),
            },
        )

        released = (
            result.scalar_one()
        )

        if released is not True:
            logger.warning(
                "Scheduler advisory lock "
                "was not reported as released"
            )

    except SQLAlchemyError as error:
        logger.warning(
            "Unable to explicitly release "
            "scheduler advisory lock: %s",
            _sanitize_error(
                error
            ),
        )

    except Exception as error:
        logger.warning(
            "Unexpected error while releasing "
            "scheduler advisory lock: %s",
            _sanitize_error(
                error
            ),
        )


def _execute_locked_cycle(
    runtime: (
        ThreatIntelligenceSchedulerRuntime
    ),
) -> (
    ThreatIntelligenceSchedulerCycleResult
    | None
):
    with (
        runtime
        .lock_engine
        .connect()
        .execution_options(
            isolation_level="AUTOCOMMIT"
        )
        as connection
    ):
        acquired = (
            _try_acquire_lock(
                connection
            )
        )

        if not acquired:
            return None

        try:
            return (
                runtime
                .cycle_service
                .run(
                    evaluated_at=(
                        datetime.now(
                            UTC
                        )
                    )
                )
            )

        finally:
            _release_lock(
                connection
            )


def _print_stage(
    *,
    name: str,
    result: (
        ThreatIntelligenceRefreshStageResult
    ),
) -> None:
    metrics = result.metrics

    print(
        f"{name}_status="
        f"{result.status}"
    )

    print(
        f"{name}_changed="
        f"{result.changed}"
    )

    print(
        f"{name}_processed="
        f"{result.processed_count}"
    )

    print(
        f"{name}_pages="
        f"{metrics.pages_processed}"
    )

    print(
        f"{name}_limit_reached="
        f"{metrics.limit_reached}"
    )

    print(
        f"{name}_records_received="
        f"{metrics.records_received}"
    )

    print(
        f"{name}_records_persisted="
        f"{metrics.records_persisted}"
    )

    print(
        f"{name}_normalization_claimed="
        f"{metrics.normalization_claimed}"
    )

    print(
        f"{name}_normalized="
        f"{metrics.normalized}"
    )

    print(
        f"{name}_already_normalized="
        f"{metrics.already_normalized}"
    )

    print(
        f"{name}_normalization_failed="
        f"{metrics.normalization_failed}"
    )

    print(
        f"{name}_canonical_records_read="
        f"{metrics.canonical_records_read}"
    )

    print(
        f"{name}_canonical_created="
        f"{metrics.canonical_created}"
    )

    print(
        f"{name}_canonical_updated="
        f"{metrics.canonical_updated}"
    )

    print(
        f"{name}_canonical_persisted="
        f"{metrics.canonical_persisted}"
    )

    if (
        result.status
        == STAGE_STATUS_FAILED
    ):
        if result.error_type:
            print(
                f"{name}_error_type="
                f"{result.error_type}"
            )

        if result.error_summary:
            print(
                f"{name}_error="
                f"{result.error_summary}"
            )


def _print_result(
    result: (
        ThreatIntelligenceSchedulerCycleResult
    ),
) -> str:
    print("")
    print(
        "================================"
    )
    print(
        "THREAT INTELLIGENCE CYCLE"
    )
    print(
        "================================"
    )

    print("")
    print("[CISA KEV]")

    _print_stage(
        name="cisa",
        result=result.cisa_kev,
    )

    print("")
    print("[GITHUB ADVISORY]")

    _print_stage(
        name="github",
        result=(
            result.github_advisory
        ),
    )

    print("")
    print("[EPSS]")

    _print_stage(
        name="epss",
        result=result.epss,
    )

    print("")
    print("[REPROCESSING]")

    print(
        "source_failures="
        f"{result.source_failure_count}"
    )

    print(
        "targets_selected="
        f"{result.reprocessing.selected_target_count}"
    )

    print(
        "targets_processed="
        f"{result.reprocessing.processed_target_count}"
    )

    print(
        "alert_transitions="
        f"{result.reprocessing.alert_transition_count}"
    )

    print(
        "alert_evaluations="
        f"{result.reprocessing.alert_evaluation_invoked_count}"
    )

    if result.has_source_failures:
        return RUN_OUTCOME_PARTIAL

    return RUN_OUTCOME_OK


def _print_database_evidence(
    evidence: (
        SchedulerDatabaseEvidence
    ),
) -> None:
    print("")
    print(
        "================================"
    )
    print(
        "DATABASE SNAPSHOT"
    )
    print(
        "================================"
    )

    print(
        "database_report_status="
        f"{evidence.status}"
    )

    if evidence.error_summary:
        print(
            "database_report_error="
            f"{evidence.error_summary}"
        )

    snapshot = evidence.snapshot

    if snapshot is not None:
        print(
            "tracked_records_total="
            f"{snapshot.tracked_records_total}"
        )

        print(
            "raw_payload_total="
            f"{snapshot.raw_payload_total}"
        )

        print(
            "raw_cisa_kev="
            f"{snapshot.raw_cisa_kev}"
        )

        print(
            "raw_github_advisory="
            f"{snapshot.raw_github_advisory}"
        )

        print(
            "raw_pending="
            f"{snapshot.raw_pending}"
        )

        print(
            "raw_processing="
            f"{snapshot.raw_processing}"
        )

        print(
            "raw_processed="
            f"{snapshot.raw_processed}"
        )

        print(
            "raw_failed="
            f"{snapshot.raw_failed}"
        )

        print(
            "normalized_cisa_kev="
            f"{snapshot.normalized_cisa_kev}"
        )

        print(
            "normalized_github_advisory="
            f"{snapshot.normalized_github_advisory}"
        )

        print(
            "epss_scores="
            f"{snapshot.epss_scores}"
        )

        print(
            "canonical_vulnerabilities="
            f"{snapshot.canonical_vulnerabilities}"
        )

        print(
            "canonical_cve_identifiers="
            f"{snapshot.canonical_cve_identifiers}"
        )

        print(
            "canonical_ghsa_identifiers="
            f"{snapshot.canonical_ghsa_identifiers}"
        )

    print("")
    print(
        "[CYCLE INGESTION ACTIVITY]"
    )

    cisa = (
        evidence.cisa_activity
    )

    github = (
        evidence.github_activity
    )

    print(
        "cisa_runs="
        f"{cisa.run_count}"
    )

    print(
        "cisa_completed_runs="
        f"{cisa.completed_runs}"
    )

    print(
        "cisa_failed_runs="
        f"{cisa.failed_runs}"
    )

    print(
        "cisa_records_received="
        f"{cisa.records_received}"
    )

    print(
        "cisa_records_succeeded="
        f"{cisa.records_succeeded}"
    )

    print(
        "cisa_records_failed="
        f"{cisa.records_failed}"
    )

    print(
        "github_runs="
        f"{github.run_count}"
    )

    print(
        "github_completed_runs="
        f"{github.completed_runs}"
    )

    print(
        "github_failed_runs="
        f"{github.failed_runs}"
    )

    print(
        "github_records_received="
        f"{github.records_received}"
    )

    print(
        "github_records_succeeded="
        f"{github.records_succeeded}"
    )

    print(
        "github_records_failed="
        f"{github.records_failed}"
    )


def _print_report_artifacts(
    artifacts: (
        SchedulerCycleReportArtifacts
    ),
) -> None:
    print("")
    print(
        "================================"
    )
    print(
        "LOCAL REPORT"
    )
    print(
        "================================"
    )

    print(
        "report_json="
        f"{artifacts.json_path}"
    )

    print(
        "report_csv="
        f"{artifacts.csv_path}"
    )


def _record_report_best_effort(
    *,
    result: (
        ThreatIntelligenceSchedulerCycleResult
    ),
    outcome: str,
    started_at: datetime,
    finished_at: datetime,
    duration_seconds: float,
) -> (
    SchedulerCycleReportArtifacts
    | None
):
    try:
        return (
            record_scheduler_cycle_report(
                result=result,
                outcome=outcome,
                started_at=started_at,
                finished_at=finished_at,
                duration_seconds=(
                    duration_seconds
                ),
            )
        )

    except Exception as error:
        sanitized = (
            _sanitize_error(
                error
            )
        )

        logger.warning(
            "Unable to write scheduler "
            "evidence report: %s",
            sanitized,
        )

        print("")
        print(
            "report_status=failed"
        )

        print(
            "report_error="
            f"{sanitized}"
        )

        return None


def _print_final_outcome(
    outcome: str,
) -> None:
    print("")
    print(
        "================================"
    )

    if (
        outcome
        == RUN_OUTCOME_PARTIAL
    ):
        print(
            "SCHEDULER_CYCLE_PARTIAL"
        )

    elif (
        outcome
        == RUN_OUTCOME_OK
    ):
        print(
            "SCHEDULER_CYCLE_OK"
        )

    elif (
        outcome
        == RUN_OUTCOME_SKIPPED
    ):
        print(
            "SCHEDULER_CYCLE_SKIPPED"
        )

    else:
        raise RuntimeError(
            "Unknown scheduler outcome"
        )

    print(
        "================================"
    )


def _run_one_cycle(
    runtime: (
        ThreatIntelligenceSchedulerRuntime
    ),
) -> str:
    started_at = datetime.now(
        UTC
    )

    performance_started_at = (
        time.perf_counter()
    )

    logger.info(
        "Threat Intelligence scheduler "
        "cycle started"
    )

    result = (
        _execute_locked_cycle(
            runtime
        )
    )

    finished_at = datetime.now(
        UTC
    )

    duration_seconds = (
        time.perf_counter()
        - performance_started_at
    )

    if result is None:
        logger.warning(
            "Threat Intelligence scheduler "
            "cycle skipped because another "
            "scheduler holds the lock"
        )

        print(
            "Another scheduler instance "
            "already holds the lock."
        )

        _print_final_outcome(
            RUN_OUTCOME_SKIPPED
        )

        return RUN_OUTCOME_SKIPPED

    outcome = (
        _print_result(
            result
        )
    )

    artifacts = (
        _record_report_best_effort(
            result=result,
            outcome=outcome,
            started_at=started_at,
            finished_at=finished_at,
            duration_seconds=(
                duration_seconds
            ),
        )
    )

    if artifacts is not None:
        _print_database_evidence(
            artifacts.database_evidence
        )

        _print_report_artifacts(
            artifacts
        )

    if (
        outcome
        == RUN_OUTCOME_PARTIAL
    ):
        logger.warning(
            "Threat Intelligence scheduler "
            "cycle completed with source failures",
            extra={
                "duration_seconds": round(
                    duration_seconds,
                    3,
                ),
                "source_failure_count": (
                    result
                    .source_failure_count
                ),
                "targets_processed": (
                    result
                    .reprocessing
                    .processed_target_count
                ),
            },
        )

    else:
        logger.info(
            "Threat Intelligence scheduler "
            "cycle completed",
            extra={
                "duration_seconds": round(
                    duration_seconds,
                    3,
                ),
                "targets_processed": (
                    result
                    .reprocessing
                    .processed_target_count
                ),
            },
        )

    print("")
    print(
        "duration_seconds="
        f"{duration_seconds:.3f}"
    )

    _print_final_outcome(
        outcome
    )

    return outcome


def _run_loop(
    *,
    runtime: (
        ThreatIntelligenceSchedulerRuntime
    ),
    interval_seconds: int,
) -> int:
    logger.info(
        "Threat Intelligence scheduler "
        "loop started",
        extra={
            "interval_seconds": (
                interval_seconds
            )
        },
    )

    print(
        "SCHEDULER_LOOP_STARTED "
        f"interval_seconds={interval_seconds}"
    )

    print(
        "Press Ctrl+C to stop."
    )

    while True:
        cycle_started_at = (
            time.monotonic()
        )

        try:
            _run_one_cycle(
                runtime
            )

        except KeyboardInterrupt:
            raise

        except Exception as error:
            sanitized = (
                _sanitize_error(
                    error
                )
            )

            logger.error(
                "Threat Intelligence scheduler "
                "cycle failed",
                extra={
                    "error_type": (
                        type(
                            error
                        ).__name__
                    ),
                    "error_summary": (
                        sanitized
                    ),
                },
            )

            print(
                "SCHEDULER_CYCLE_FAILED: "
                f"{sanitized}",
                file=sys.stderr,
            )

        elapsed = (
            time.monotonic()
            - cycle_started_at
        )

        sleep_seconds = max(
            interval_seconds
            - elapsed,
            0.0,
        )

        try:
            time.sleep(
                sleep_seconds
            )

        except KeyboardInterrupt:
            raise


def _sanitize_error(
    error: BaseException,
) -> str:
    message = str(
        error
    ).strip()

    raw = (
        f"{type(error).__name__}: "
        f"{message}"
        if message
        else type(error).__name__
    )

    return (
        redact_sensitive_data(
            raw,
            max_length=500,
        )
    )


def main() -> int:
    configure_logging()

    arguments = (
        _parse_arguments()
    )

    try:
        runtime = (
            build_threat_intelligence_scheduler_runtime()
        )

        if arguments.once:
            outcome = (
                _run_one_cycle(
                    runtime
                )
            )

            if (
                outcome
                == RUN_OUTCOME_SKIPPED
            ):
                return 2

            return 0

        interval_seconds = (
            _read_interval_seconds(
                arguments.interval_seconds
            )
        )

        return _run_loop(
            runtime=runtime,
            interval_seconds=(
                interval_seconds
            ),
        )

    except KeyboardInterrupt:
        logger.info(
            "Threat Intelligence scheduler "
            "stopped by operator"
        )

        print("")
        print(
            "SCHEDULER_STOPPED"
        )

        return 0

    except Exception as error:
        sanitized = (
            _sanitize_error(
                error
            )
        )

        logger.error(
            "Threat Intelligence scheduler "
            "failed",
            extra={
                "error_type": (
                    type(
                        error
                    ).__name__
                ),
                "error_summary": (
                    sanitized
                ),
            },
        )

        print(
            "SCHEDULER_FAILED: "
            f"{sanitized}",
            file=sys.stderr,
        )

        return 1


if __name__ == "__main__":
    raise SystemExit(
        main()
    )