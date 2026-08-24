from __future__ import annotations

from pathlib import Path

from application.services.reevaluate_threat_intelligence_targets_service import (
    ReevaluateThreatIntelligenceTargetsResult,
)
from application.services.threat_intelligence_scheduler_cycle_service import (
    STAGE_STATUS_FAILED,
    ThreatIntelligenceRefreshStageResult,
    ThreatIntelligenceSchedulerCycleResult,
    ThreatIntelligenceStageMetrics,
)
from infrastructure.cli import (
    scheduler as scheduler_cli,
)
from infrastructure.scheduler.cycle_reporting import (
    DATABASE_STATUS_COMPLETED,
    SchedulerCycleReportArtifacts,
    SchedulerDatabaseEvidence,
    SchedulerDatabaseSnapshot,
    SchedulerSourceIngestionActivity,
)


def _reprocessing_result():
    return (
        ReevaluateThreatIntelligenceTargetsResult(
            cisa_kev_changed=True,
            github_advisory_changed=False,
            epss_changed=True,
            selected_target_count=2,
            processed_target_count=2,
            alert_transition_count=1,
            alert_evaluation_invoked_count=1,
        )
    )


def _completed_stage(
    *,
    changed: bool,
    processed_count: int,
):
    return (
        ThreatIntelligenceRefreshStageResult(
            changed=changed,
            processed_count=(
                processed_count
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
            ),
        )
    )


def _failed_stage():
    return (
        ThreatIntelligenceRefreshStageResult(
            changed=False,
            processed_count=0,
            status=STAGE_STATUS_FAILED,
            error_type=(
                "GitHubAdvisoryConnectorError"
            ),
            error_summary=(
                "GitHub Advisory API "
                "request timed out."
            ),
        )
    )


def _ok_result():
    return (
        ThreatIntelligenceSchedulerCycleResult(
            cisa_kev=_completed_stage(
                changed=True,
                processed_count=10,
            ),
            github_advisory=(
                _completed_stage(
                    changed=True,
                    processed_count=20,
                )
            ),
            epss=_completed_stage(
                changed=True,
                processed_count=5,
            ),
            reprocessing=(
                _reprocessing_result()
            ),
        )
    )


def _partial_result():
    return (
        ThreatIntelligenceSchedulerCycleResult(
            cisa_kev=_completed_stage(
                changed=True,
                processed_count=10,
            ),
            github_advisory=(
                _failed_stage()
            ),
            epss=_completed_stage(
                changed=True,
                processed_count=5,
            ),
            reprocessing=(
                _reprocessing_result()
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
                    raw_payload_total=1000,
                    raw_cisa_kev=200,
                    raw_github_advisory=700,
                    raw_pending=5,
                    raw_processing=0,
                    raw_processed=990,
                    raw_failed=5,
                    normalized_cisa_kev=200,
                    normalized_github_advisory=650,
                    epss_scores=100,
                    canonical_vulnerabilities=700,
                    canonical_cve_identifiers=600,
                    canonical_ghsa_identifiers=550,
                )
            ),
            cisa_activity=(
                SchedulerSourceIngestionActivity(
                    run_count=1,
                    completed_runs=1,
                    failed_runs=0,
                    records_received=200,
                    records_succeeded=200,
                    records_failed=0,
                )
            ),
            github_activity=(
                SchedulerSourceIngestionActivity(
                    run_count=5,
                    completed_runs=5,
                    failed_runs=0,
                    records_received=500,
                    records_succeeded=480,
                    records_failed=0,
                )
            ),
        )
    )


def test_print_result_reports_ok(
    capsys,
):
    outcome = (
        scheduler_cli
        ._print_result(
            _ok_result()
        )
    )

    output = (
        capsys
        .readouterr()
        .out
    )

    assert (
        outcome
        == scheduler_cli.RUN_OUTCOME_OK
    )

    assert (
        "source_failures=0"
        in output
    )

    assert (
        "github_pages=5"
        in output
    )

    assert (
        "github_records_persisted=480"
        in output
    )

    assert (
        "github_normalized=470"
        in output
    )

    assert (
        "github_canonical_created=300"
        in output
    )

    assert (
        "github_limit_reached=True"
        in output
    )


def test_print_result_reports_partial(
    capsys,
):
    outcome = (
        scheduler_cli
        ._print_result(
            _partial_result()
        )
    )

    output = (
        capsys
        .readouterr()
        .out
    )

    assert (
        outcome
        == scheduler_cli
        .RUN_OUTCOME_PARTIAL
    )

    assert (
        "github_status=failed"
        in output
    )

    assert (
        "github_error_type="
        "GitHubAdvisoryConnectorError"
        in output
    )

    assert (
        "source_failures=1"
        in output
    )


def test_database_evidence_is_printed(
    capsys,
):
    scheduler_cli._print_database_evidence(
        _database_evidence()
    )

    output = (
        capsys
        .readouterr()
        .out
    )

    assert (
        "DATABASE SNAPSHOT"
        in output
    )

    assert (
        "raw_payload_total=1000"
        in output
    )

    assert (
        "normalized_github_advisory=650"
        in output
    )

    assert (
        "canonical_cve_identifiers=600"
        in output
    )

    assert (
        "github_runs=5"
        in output
    )


def test_run_one_cycle_writes_report(
    monkeypatch,
    capsys,
    tmp_path,
):
    result = _ok_result()

    artifacts = (
        SchedulerCycleReportArtifacts(
            json_path=(
                Path(tmp_path)
                / "cycle.json"
            ),
            csv_path=(
                Path(tmp_path)
                / "cycles.csv"
            ),
            database_evidence=(
                _database_evidence()
            ),
        )
    )

    monkeypatch.setattr(
        scheduler_cli,
        "_execute_locked_cycle",
        lambda runtime: result,
    )

    monkeypatch.setattr(
        scheduler_cli,
        "_record_report_best_effort",
        lambda **kwargs: artifacts,
    )

    outcome = (
        scheduler_cli
        ._run_one_cycle(
            object() # type: ignore
        )
    )

    output = (
        capsys
        .readouterr()
        .out
    )

    assert (
        outcome
        == scheduler_cli.RUN_OUTCOME_OK
    )

    assert (
        "LOCAL REPORT"
        in output
    )

    assert (
        "report_json="
        in output
    )

    assert (
        "report_csv="
        in output
    )

    assert (
        "SCHEDULER_CYCLE_OK"
        in output
    )


def test_run_one_cycle_returns_partial(
    monkeypatch,
    capsys,
    tmp_path,
):
    result = (
        _partial_result()
    )

    artifacts = (
        SchedulerCycleReportArtifacts(
            json_path=(
                Path(tmp_path)
                / "cycle.json"
            ),
            csv_path=(
                Path(tmp_path)
                / "cycles.csv"
            ),
            database_evidence=(
                _database_evidence()
            ),
        )
    )

    monkeypatch.setattr(
        scheduler_cli,
        "_execute_locked_cycle",
        lambda runtime: result,
    )

    monkeypatch.setattr(
        scheduler_cli,
        "_record_report_best_effort",
        lambda **kwargs: artifacts,
    )

    outcome = (
        scheduler_cli
        ._run_one_cycle(
            object() # type: ignore
        )
    )

    output = (
        capsys
        .readouterr()
        .out
    )

    assert (
        outcome
        == scheduler_cli
        .RUN_OUTCOME_PARTIAL
    )

    assert (
        "SCHEDULER_CYCLE_PARTIAL"
        in output
    )


def test_run_one_cycle_reports_skipped(
    monkeypatch,
    capsys,
):
    monkeypatch.setattr(
        scheduler_cli,
        "_execute_locked_cycle",
        lambda runtime: None,
    )

    outcome = (
        scheduler_cli
        ._run_one_cycle(
            object() # type: ignore
        )
    )

    output = (
        capsys
        .readouterr()
        .out
    )

    assert (
        outcome
        == scheduler_cli
        .RUN_OUTCOME_SKIPPED
    )

    assert (
        "SCHEDULER_CYCLE_SKIPPED"
        in output
    )