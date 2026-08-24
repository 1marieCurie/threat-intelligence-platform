from __future__ import annotations

import csv
import json
from dataclasses import (
    asdict,
    dataclass,
)
from datetime import datetime
from pathlib import Path
from typing import Any

from sqlalchemy import (
    case,
    func,
    select,
)
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from application.security.sensitive_data_redactor import (
    redact_sensitive_data,
)
from application.services.threat_intelligence_scheduler_cycle_service import (
    ThreatIntelligenceRefreshStageResult,
    ThreatIntelligenceSchedulerCycleResult,
)
from infrastructure.persistence.models.canonical import (
    CanonicalVulnerabilityIdentifierModel,
    CanonicalVulnerabilityModel,
)
from infrastructure.persistence.models.normalized import (
    CisaKevVulnerabilityModel,
    EPSSScoreModel,
    GitHubAdvisoryVulnerabilityModel,
)
from infrastructure.persistence.models.ops import (
    IngestionRunModel,
    SourceModel,
)
from infrastructure.persistence.models.raw import (
    SourcePayloadModel,
)
from infrastructure.persistence.sqlalchemy.engine import (
    create_ingestion_engine,
)
from infrastructure.persistence.sqlalchemy.session import (
    create_session_factory,
)


PROJECT_ROOT = (
    Path(__file__)
    .resolve()
    .parents[2]
)

DEFAULT_REPORT_ROOT = (
    PROJECT_ROOT
    / "artifacts"
    / "reports"
    / "scheduler"
)


CISA_SOURCE_CODE = "CISA_KEV"

GITHUB_SOURCE_CODE = (
    "GITHUB_ADVISORY"
)


DATABASE_STATUS_COMPLETED = (
    "completed"
)

DATABASE_STATUS_FAILED = (
    "failed"
)


@dataclass(
    frozen=True,
    slots=True,
)
class SchedulerSourceIngestionActivity:
    run_count: int = 0

    completed_runs: int = 0
    failed_runs: int = 0

    records_received: int = 0
    records_succeeded: int = 0
    records_failed: int = 0


@dataclass(
    frozen=True,
    slots=True,
)
class SchedulerDatabaseSnapshot:
    """
    Snapshot technique des principales tables utilisées
    par le pipeline de vulnérabilités.

    tracked_records_total n'est volontairement PAS présenté
    comme le nombre de lignes de toute la base PostgreSQL.

    Il s'agit uniquement de la somme des tables suivies ici.
    """

    raw_payload_total: int

    raw_cisa_kev: int
    raw_github_advisory: int

    raw_pending: int
    raw_processing: int
    raw_processed: int
    raw_failed: int

    normalized_cisa_kev: int
    normalized_github_advisory: int

    epss_scores: int

    canonical_vulnerabilities: int

    canonical_cve_identifiers: int
    canonical_ghsa_identifiers: int

    @property
    def tracked_records_total(
        self,
    ) -> int:
        return (
            self.raw_payload_total
            + self.normalized_cisa_kev
            + self.normalized_github_advisory
            + self.epss_scores
            + self.canonical_vulnerabilities
            + self.canonical_cve_identifiers
            + self.canonical_ghsa_identifiers
        )


@dataclass(
    frozen=True,
    slots=True,
)
class SchedulerDatabaseEvidence:
    status: str

    error_summary: str | None

    snapshot: (
        SchedulerDatabaseSnapshot
        | None
    )

    cisa_activity: (
        SchedulerSourceIngestionActivity
    )

    github_activity: (
        SchedulerSourceIngestionActivity
    )


@dataclass(
    frozen=True,
    slots=True,
)
class SchedulerCycleReportArtifacts:
    json_path: Path
    csv_path: Path

    database_evidence: (
        SchedulerDatabaseEvidence
    )


def record_scheduler_cycle_report(
    *,
    result: (
        ThreatIntelligenceSchedulerCycleResult
    ),
    outcome: str,
    started_at: datetime,
    finished_at: datetime,
    duration_seconds: float,
    output_root: Path | None = None,
) -> SchedulerCycleReportArtifacts:
    """
    Point d'entrée utilisé par le CLI.

    1. lit un snapshot PostgreSQL ;
    2. construit le rapport du cycle ;
    3. écrit un JSON détaillé ;
    4. ajoute une ligne au CSV cumulatif.

    Cette fonction n'altère aucune donnée métier.
    """

    _validate_datetime(
        started_at,
        "started_at",
    )

    _validate_datetime(
        finished_at,
        "finished_at",
    )

    if (
        isinstance(
            duration_seconds,
            bool,
        )
        or not isinstance(
            duration_seconds,
            (int, float),
        )
        or duration_seconds < 0
    ):
        raise ValueError(
            "duration_seconds must be "
            "a non-negative number"
        )

    engine = (
        create_ingestion_engine()
    )

    try:
        session_factory = (
            create_session_factory(
                engine
            )
        )

        database_evidence = (
            collect_scheduler_database_evidence(
                session_factory=(
                    session_factory
                ),
                started_at=started_at,
                finished_at=finished_at,
            )
        )

    finally:
        engine.dispose()

    return write_scheduler_cycle_report(
        result=result,
        outcome=outcome,
        started_at=started_at,
        finished_at=finished_at,
        duration_seconds=float(
            duration_seconds
        ),
        database_evidence=(
            database_evidence
        ),
        output_root=output_root,
    )


def collect_scheduler_database_evidence(
    *,
    session_factory,
    started_at: datetime,
    finished_at: datetime,
) -> SchedulerDatabaseEvidence:
    """
    Les lectures sont best-effort.

    Une impossibilité de générer les statistiques du rapport
    ne doit jamais transformer un cycle métier réussi en
    échec du scheduler.
    """

    try:
        with (
            session_factory()
            as session
        ):
            snapshot = (
                _read_database_snapshot(
                    session
                )
            )

            cisa_activity = (
                _read_source_activity(
                    session=session,
                    source_code=(
                        CISA_SOURCE_CODE
                    ),
                    started_at=started_at,
                    finished_at=finished_at,
                )
            )

            github_activity = (
                _read_source_activity(
                    session=session,
                    source_code=(
                        GITHUB_SOURCE_CODE
                    ),
                    started_at=started_at,
                    finished_at=finished_at,
                )
            )

        return (
            SchedulerDatabaseEvidence(
                status=(
                    DATABASE_STATUS_COMPLETED
                ),
                error_summary=None,
                snapshot=snapshot,
                cisa_activity=(
                    cisa_activity
                ),
                github_activity=(
                    github_activity
                ),
            )
        )

    except Exception as error:
        return (
            SchedulerDatabaseEvidence(
                status=(
                    DATABASE_STATUS_FAILED
                ),
                error_summary=(
                    _sanitize_error(
                        error
                    )
                ),
                snapshot=None,
                cisa_activity=(
                    SchedulerSourceIngestionActivity()
                ),
                github_activity=(
                    SchedulerSourceIngestionActivity()
                ),
            )
        )


def _read_database_snapshot(
    session: Session,
) -> SchedulerDatabaseSnapshot:
    raw_payload_total = (
        _count_model(
            session,
            SourcePayloadModel,
        )
    )

    raw_cisa_kev = (
        _count_raw_for_source(
            session=session,
            source_code=(
                CISA_SOURCE_CODE
            ),
        )
    )

    raw_github_advisory = (
        _count_raw_for_source(
            session=session,
            source_code=(
                GITHUB_SOURCE_CODE
            ),
        )
    )

    raw_pending = (
        _count_raw_status(
            session=session,
            status="pending",
        )
    )

    raw_processing = (
        _count_raw_status(
            session=session,
            status="processing",
        )
    )

    raw_processed = (
        _count_raw_status(
            session=session,
            status="processed",
        )
    )

    raw_failed = (
        _count_raw_status(
            session=session,
            status="failed",
        )
    )

    normalized_cisa_kev = (
        _count_model(
            session,
            CisaKevVulnerabilityModel,
        )
    )

    normalized_github_advisory = (
        _count_model(
            session,
            GitHubAdvisoryVulnerabilityModel,
        )
    )

    epss_scores = (
        _count_model(
            session,
            EPSSScoreModel,
        )
    )

    canonical_vulnerabilities = (
        _count_model(
            session,
            CanonicalVulnerabilityModel,
        )
    )

    canonical_cve_identifiers = (
        _count_canonical_identifiers(
            session=session,
            namespace="CVE",
        )
    )

    canonical_ghsa_identifiers = (
        _count_canonical_identifiers(
            session=session,
            namespace="GHSA",
        )
    )

    return (
        SchedulerDatabaseSnapshot(
            raw_payload_total=(
                raw_payload_total
            ),
            raw_cisa_kev=(
                raw_cisa_kev
            ),
            raw_github_advisory=(
                raw_github_advisory
            ),
            raw_pending=(
                raw_pending
            ),
            raw_processing=(
                raw_processing
            ),
            raw_processed=(
                raw_processed
            ),
            raw_failed=(
                raw_failed
            ),
            normalized_cisa_kev=(
                normalized_cisa_kev
            ),
            normalized_github_advisory=(
                normalized_github_advisory
            ),
            epss_scores=(
                epss_scores
            ),
            canonical_vulnerabilities=(
                canonical_vulnerabilities
            ),
            canonical_cve_identifiers=(
                canonical_cve_identifiers
            ),
            canonical_ghsa_identifiers=(
                canonical_ghsa_identifiers
            ),
        )
    )


def _read_source_activity(
    *,
    session: Session,
    source_code: str,
    started_at: datetime,
    finished_at: datetime,
) -> SchedulerSourceIngestionActivity:
    statement = (
        select(
            func.count(
                IngestionRunModel.id
            ),
            func.sum(
                case(
                    (
                        IngestionRunModel.status
                        == "completed",
                        1,
                    ),
                    else_=0,
                )
            ),
            func.sum(
                case(
                    (
                        IngestionRunModel.status
                        == "failed",
                        1,
                    ),
                    else_=0,
                )
            ),
            func.sum(
                IngestionRunModel
                .records_received
            ),
            func.sum(
                IngestionRunModel
                .records_succeeded
            ),
            func.sum(
                IngestionRunModel
                .records_failed
            ),
        )
        .select_from(
            IngestionRunModel
        )
        .join(
            SourceModel,
            (
                SourceModel.id
                == IngestionRunModel.source_id
            ),
        )
        .where(
            SourceModel.code
            == source_code,
            IngestionRunModel.started_at
            >= started_at,
            IngestionRunModel.started_at
            <= finished_at,
        )
    )

    row = (
        session.execute(
            statement
        )
        .one()
    )

    return (
        SchedulerSourceIngestionActivity(
            run_count=_int_or_zero(
                row[0]
            ),
            completed_runs=_int_or_zero(
                row[1]
            ),
            failed_runs=_int_or_zero(
                row[2]
            ),
            records_received=_int_or_zero(
                row[3]
            ),
            records_succeeded=_int_or_zero(
                row[4]
            ),
            records_failed=_int_or_zero(
                row[5]
            ),
        )
    )


def _count_model(
    session: Session,
    model,
) -> int:
    value = session.scalar(
        select(
            func.count()
        )
        .select_from(
            model
        )
    )

    return _int_or_zero(
        value
    )


def _count_raw_for_source(
    *,
    session: Session,
    source_code: str,
) -> int:
    value = session.scalar(
        select(
            func.count(
                SourcePayloadModel.id
            )
        )
        .select_from(
            SourcePayloadModel
        )
        .join(
            SourceModel,
            (
                SourceModel.id
                == SourcePayloadModel.source_id
            ),
        )
        .where(
            SourceModel.code
            == source_code
        )
    )

    return _int_or_zero(
        value
    )


def _count_raw_status(
    *,
    session: Session,
    status: str,
) -> int:
    value = session.scalar(
        select(
            func.count(
                SourcePayloadModel.id
            )
        )
        .where(
            SourcePayloadModel
            .processing_status
            == status
        )
    )

    return _int_or_zero(
        value
    )


def _count_canonical_identifiers(
    *,
    session: Session,
    namespace: str,
) -> int:
    value = session.scalar(
        select(
            func.count(
                CanonicalVulnerabilityIdentifierModel
                .id
            )
        )
        .where(
            CanonicalVulnerabilityIdentifierModel
            .namespace
            == namespace
        )
    )

    return _int_or_zero(
        value
    )


def write_scheduler_cycle_report(
    *,
    result: (
        ThreatIntelligenceSchedulerCycleResult
    ),
    outcome: str,
    started_at: datetime,
    finished_at: datetime,
    duration_seconds: float,
    database_evidence: (
        SchedulerDatabaseEvidence
    ),
    output_root: Path | None = None,
) -> SchedulerCycleReportArtifacts:
    report_root = (
        DEFAULT_REPORT_ROOT
        if output_root is None
        else Path(
            output_root
        )
    )

    cycles_directory = (
        report_root
        / "cycles"
    )

    cycles_directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    report = (
        _build_report_dictionary(
            result=result,
            outcome=outcome,
            started_at=started_at,
            finished_at=finished_at,
            duration_seconds=(
                duration_seconds
            ),
            database_evidence=(
                database_evidence
            ),
        )
    )

    timestamp = (
        finished_at
        .strftime(
            "%Y%m%dT%H%M%S%fZ"
        )
    )

    json_path = (
        cycles_directory
        / (
            "scheduler_cycle_"
            f"{timestamp}.json"
        )
    )

    csv_path = (
        report_root
        / "scheduler_cycles.csv"
    )

    _write_json_atomic(
        path=json_path,
        report=report,
    )

    _append_csv(
        path=csv_path,
        report=report,
    )

    return (
        SchedulerCycleReportArtifacts(
            json_path=json_path,
            csv_path=csv_path,
            database_evidence=(
                database_evidence
            ),
        )
    )


def _build_report_dictionary(
    *,
    result: (
        ThreatIntelligenceSchedulerCycleResult
    ),
    outcome: str,
    started_at: datetime,
    finished_at: datetime,
    duration_seconds: float,
    database_evidence: (
        SchedulerDatabaseEvidence
    ),
) -> dict[str, Any]:
    return {
        "report_version": (
            "scheduler-report/v1"
        ),
        "outcome": outcome,
        "started_at": (
            started_at.isoformat()
        ),
        "finished_at": (
            finished_at.isoformat()
        ),
        "duration_seconds": round(
            duration_seconds,
            3,
        ),
        "source_failure_count": (
            result.source_failure_count
        ),
        "sources": {
            "cisa_kev": (
                _stage_to_dictionary(
                    result.cisa_kev
                )
            ),
            "github_advisory": (
                _stage_to_dictionary(
                    result.github_advisory
                )
            ),
            "epss": (
                _stage_to_dictionary(
                    result.epss
                )
            ),
        },
        "reprocessing": {
            "selected_target_count": (
                result
                .reprocessing
                .selected_target_count
            ),
            "processed_target_count": (
                result
                .reprocessing
                .processed_target_count
            ),
            "alert_transition_count": (
                result
                .reprocessing
                .alert_transition_count
            ),
            (
                "alert_evaluation_"
                "invoked_count"
            ): (
                result
                .reprocessing
                .alert_evaluation_invoked_count
            ),
        },
        "database": (
            _database_evidence_to_dictionary(
                database_evidence
            )
        ),
    }


def _stage_to_dictionary(
    stage: (
        ThreatIntelligenceRefreshStageResult
    ),
) -> dict[str, Any]:
    return {
        "status": stage.status,
        "changed": stage.changed,
        "processed_count": (
            stage.processed_count
        ),
        "error_type": (
            stage.error_type
        ),
        "error_summary": (
            stage.error_summary
        ),
        "metrics": (
            asdict(
                stage.metrics
            )
        ),
    }


def _database_evidence_to_dictionary(
    evidence: SchedulerDatabaseEvidence,
) -> dict[str, Any]:
    snapshot_dictionary: (
        dict[str, Any]
        | None
    )

    if evidence.snapshot is None:
        snapshot_dictionary = None

    else:
        snapshot_dictionary = (
            asdict(
                evidence.snapshot
            )
        )

        snapshot_dictionary[
            "tracked_records_total"
        ] = (
            evidence
            .snapshot
            .tracked_records_total
        )

    return {
        "status": evidence.status,
        "error_summary": (
            evidence.error_summary
        ),
        "snapshot": (
            snapshot_dictionary
        ),
        "cycle_ingestion_activity": {
            "cisa_kev": asdict(
                evidence.cisa_activity
            ),
            "github_advisory": asdict(
                evidence.github_activity
            ),
        },
    }


def _write_json_atomic(
    *,
    path: Path,
    report: dict[str, Any],
) -> None:
    temporary_path = (
        path.with_suffix(
            path.suffix
            + ".tmp"
        )
    )

    with temporary_path.open(
        "w",
        encoding="utf-8",
        newline="\n",
    ) as file:
        json.dump(
            report,
            file,
            indent=2,
            ensure_ascii=False,
            sort_keys=True,
        )

        file.write("\n")

    temporary_path.replace(
        path
    )


def _append_csv(
    *,
    path: Path,
    report: dict[str, Any],
) -> None:
    flattened = (
        _flatten_dictionary(
            report
        )
    )

    field_names = sorted(
        flattened.keys()
    )

    file_exists = (
        path.exists()
    )

    if file_exists:
        with path.open(
            "r",
            encoding="utf-8",
            newline="",
        ) as existing_file:
            reader = csv.reader(
                existing_file
            )

            existing_header = next(
                reader,
                None,
            )

        if (
            existing_header is not None
            and existing_header
            != field_names
        ):
            raise RuntimeError(
                "Existing scheduler CSV "
                "header does not match "
                "report schema"
            )

    with path.open(
        "a",
        encoding="utf-8",
        newline="",
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=field_names,
            extrasaction="ignore",
        )

        if not file_exists:
            writer.writeheader()

        writer.writerow(
            flattened
        )


def _flatten_dictionary(
    value: dict[str, Any],
    *,
    prefix: str = "",
) -> dict[str, Any]:
    flattened: dict[
        str,
        Any,
    ] = {}

    for key, item in value.items():
        normalized_key = (
            str(key)
        )

        full_key = (
            normalized_key
            if not prefix
            else (
                f"{prefix}."
                f"{normalized_key}"
            )
        )

        if isinstance(
            item,
            dict,
        ):
            flattened.update(
                _flatten_dictionary(
                    item,
                    prefix=full_key,
                )
            )

        else:
            flattened[
                full_key
            ] = (
                ""
                if item is None
                else item
            )

    return flattened


def _int_or_zero(
    value: object,
) -> int:
    if value is None:
        return 0

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
        raise RuntimeError(
            "Database count returned "
            "an invalid value"
        )

    if value < 0:
        raise RuntimeError(
            "Database count returned "
            "a negative value"
        )

    return value


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


def _validate_datetime(
    value: datetime,
    field_name: str,
) -> None:
    if not isinstance(
        value,
        datetime,
    ):
        raise TypeError(
            f"{field_name} "
            "must be a datetime"
        )

    if value.tzinfo is None:
        raise ValueError(
            f"{field_name} "
            "must be timezone-aware"
        )