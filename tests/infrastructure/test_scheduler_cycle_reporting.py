from __future__ import annotations

import csv
import json
from datetime import (
    UTC,
    datetime,
)

from application.services.reevaluate_threat_intelligence_targets_service import (
    ReevaluateThreatIntelligenceTargetsResult,
)
from application.services.threat_intelligence_scheduler_cycle_service import (
    STAGE_STATUS_FAILED,
    ThreatIntelligenceRefreshStageResult,
    ThreatIntelligenceSchedulerCycleResult,
    ThreatIntelligenceStageMetrics,
)
from infrastructure.scheduler.cycle_reporting import (
    DATABASE_STATUS_COMPLETED,
    SchedulerDatabaseEvidence,
    SchedulerDatabaseSnapshot,
    SchedulerSourceIngestionActivity,
    write_scheduler_cycle_report,
)


STARTED_AT = datetime(
    2026,
    8,
    24,
    16,
    40,
    tzinfo=UTC,
)

FINISHED_AT = datetime(
    2026,
    8,
    24,
    16,
    42,
    tzinfo=UTC,
)


def _stage(
    *,
    changed: bool,
    failed: bool = False,
):
    return (
        ThreatIntelligenceRefreshStageResult(
            changed=(
                False
                if failed
                else changed
            ),
            processed_count=(
                0
                if failed
                else 200
            ),
            status=(
                STAGE_STATUS_FAILED
                if failed
                else "completed"
            ),
            error_type=(
                "ProviderTimeout"
                if failed
                else None
            ),
            error_summary=(
                "Provider timed out"
                if failed
                else None
            ),
            metrics=(
                ThreatIntelligenceStageMetrics(
                    pages_processed=5,
                    records_received=500,
                    records_persisted=480,
                    normalization_claimed=480,
                    normalized=470,
                    already_normalized=8,
                    normalization_failed=2,
                    canonical_records_read=470,
                    canonical_created=300,
                    canonical_updated=160,
                    canonical_persisted=460,
                    limit_reached=True,
                )
                if not failed
                else (
                    ThreatIntelligenceStageMetrics()
                )
            ),
        )
    )


def _result():
    return (
        ThreatIntelligenceSchedulerCycleResult(
            cisa_kev=_stage(
                changed=True
            ),
            github_advisory=_stage(
                changed=True
            ),
            epss=_stage(
                changed=False,
                failed=True,
            ),
            reprocessing=(
                ReevaluateThreatIntelligenceTargetsResult(
                    cisa_kev_changed=True,
                    github_advisory_changed=True,
                    epss_changed=False,
                    selected_target_count=3,
                    processed_target_count=3,
                    alert_transition_count=1,
                    alert_evaluation_invoked_count=1,
                )
            ),
        )
    )


def _database_evidence():
    return (
        SchedulerDatabaseEvidence(
            status=(
                DATABASE_STATUS_COMPLETED
            ),
            error_summary=None,
            snapshot=(
                SchedulerDatabaseSnapshot(
                    raw_payload_total=10_000,
                    raw_cisa_kev=1_695,
                    raw_github_advisory=8_000,
                    raw_pending=20,
                    raw_processing=0,
                    raw_processed=9_970,
                    raw_failed=10,
                    normalized_cisa_kev=1_695,
                    normalized_github_advisory=7_500,
                    epss_scores=400,
                    canonical_vulnerabilities=8_500,
                    canonical_cve_identifiers=7_000,
                    canonical_ghsa_identifiers=6_000,
                )
            ),
            cisa_activity=(
                SchedulerSourceIngestionActivity(
                    run_count=1,
                    completed_runs=1,
                    failed_runs=0,
                    records_received=1_695,
                    records_succeeded=1_695,
                    records_failed=0,
                )
            ),
            github_activity=(
                SchedulerSourceIngestionActivity(
                    run_count=6,
                    completed_runs=5,
                    failed_runs=1,
                    records_received=500,
                    records_succeeded=480,
                    records_failed=0,
                )
            ),
        )
    )


def test_snapshot_tracks_explicit_total():
    snapshot = (
        _database_evidence()
        .snapshot
    )

    assert snapshot is not None

    expected = (
        10_000
        + 1_695
        + 7_500
        + 400
        + 8_500
        + 7_000
        + 6_000
    )

    assert (
        snapshot.tracked_records_total
        == expected
    )


def test_report_writes_json_and_csv(
    tmp_path,
):
    artifacts = (
        write_scheduler_cycle_report(
            result=_result(),
            outcome="partial",
            started_at=STARTED_AT,
            finished_at=FINISHED_AT,
            duration_seconds=120.5,
            database_evidence=(
                _database_evidence()
            ),
            output_root=tmp_path,
        )
    )

    assert (
        artifacts.json_path.exists()
    )

    assert (
        artifacts.csv_path.exists()
    )

    report = json.loads(
        artifacts
        .json_path
        .read_text(
            encoding="utf-8"
        )
    )

    assert (
        report["outcome"]
        == "partial"
    )

    assert (
        report[
            "sources"
        ][
            "github_advisory"
        ][
            "metrics"
        ][
            "records_persisted"
        ]
        == 480
    )

    assert (
        report[
            "sources"
        ][
            "github_advisory"
        ][
            "metrics"
        ][
            "limit_reached"
        ]
        is True
    )

    assert (
        report[
            "database"
        ][
            "snapshot"
        ][
            "canonical_cve_identifiers"
        ]
        == 7_000
    )

    assert (
        report[
            "database"
        ][
            "cycle_ingestion_activity"
        ][
            "github_advisory"
        ][
            "failed_runs"
        ]
        == 1
    )

    with (
        artifacts.csv_path.open(
            "r",
            encoding="utf-8",
            newline="",
        )
        as file
    ):
        rows = list(
            csv.DictReader(
                file
            )
        )

    assert len(rows) == 1

    assert (
        rows[0][
            "outcome"
        ]
        == "partial"
    )


def test_report_appends_csv_history(
    tmp_path,
):
    for _ in range(2):
        write_scheduler_cycle_report(
            result=_result(),
            outcome="partial",
            started_at=STARTED_AT,
            finished_at=FINISHED_AT,
            duration_seconds=120.5,
            database_evidence=(
                _database_evidence()
            ),
            output_root=tmp_path,
        )

    with (
        (
            tmp_path
            / "scheduler_cycles.csv"
        )
        .open(
            "r",
            encoding="utf-8",
            newline="",
        )
        as file
    ):
        rows = list(
            csv.DictReader(
                file
            )
        )

    assert len(rows) == 2