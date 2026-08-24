from __future__ import annotations

from dataclasses import (
    dataclass,
    field,
)
from datetime import datetime
from typing import Protocol

from application.security.sensitive_data_redactor import (
    redact_sensitive_data,
)
from application.services.reevaluate_threat_intelligence_targets_service import (
    ReevaluateThreatIntelligenceTargetsResult,
)
from domain._asset_validation import (
    normalize_datetime_utc,
)


STAGE_STATUS_COMPLETED = "completed"
STAGE_STATUS_FAILED = "failed"


@dataclass(
    frozen=True,
    slots=True,
)
class ThreatIntelligenceStageMetrics:
    """
    Métriques techniques d'une source pendant un cycle.

    Elles sont destinées :
    - au terminal ;
    - aux rapports locaux ;
    - aux graphiques du mémoire.

    Elles ne participent à aucune règle métier.
    """

    pages_processed: int = 0

    records_received: int = 0
    records_persisted: int = 0

    normalization_claimed: int = 0
    normalized: int = 0
    already_normalized: int = 0
    normalization_failed: int = 0

    canonical_records_read: int = 0
    canonical_created: int = 0
    canonical_updated: int = 0
    canonical_persisted: int = 0

    limit_reached: bool = False

    def __post_init__(
        self,
    ) -> None:
        integer_fields = (
            "pages_processed",
            "records_received",
            "records_persisted",
            "normalization_claimed",
            "normalized",
            "already_normalized",
            "normalization_failed",
            "canonical_records_read",
            "canonical_created",
            "canonical_updated",
            "canonical_persisted",
        )

        for field_name in integer_fields:
            value = getattr(
                self,
                field_name,
            )

            if (
                isinstance(value, bool)
                or not isinstance(
                    value,
                    int,
                )
                or value < 0
            ):
                raise ValueError(
                    f"{field_name} must be "
                    "a non-negative integer"
                )

        if not isinstance(
            self.limit_reached,
            bool,
        ):
            raise TypeError(
                "limit_reached must be a boolean"
            )


@dataclass(
    frozen=True,
    slots=True,
)
class ThreatIntelligenceRefreshStageResult:
    changed: bool

    processed_count: int = 0

    status: str = STAGE_STATUS_COMPLETED

    error_type: str | None = None
    error_summary: str | None = None

    metrics: (
        ThreatIntelligenceStageMetrics
    ) = field(
        default_factory=(
            ThreatIntelligenceStageMetrics
        )
    )

    @property
    def succeeded(
        self,
    ) -> bool:
        return (
            self.status
            == STAGE_STATUS_COMPLETED
        )

    @property
    def failed(
        self,
    ) -> bool:
        return (
            self.status
            == STAGE_STATUS_FAILED
        )


class ThreatIntelligenceRefreshStage(
    Protocol
):
    def run(
        self,
    ) -> ThreatIntelligenceRefreshStageResult:
        ...


class ThreatIntelligenceTargetReevaluator(
    Protocol
):
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
        ...


@dataclass(
    frozen=True,
    slots=True,
)
class ThreatIntelligenceSchedulerCycleResult:
    cisa_kev: (
        ThreatIntelligenceRefreshStageResult
    )

    github_advisory: (
        ThreatIntelligenceRefreshStageResult
    )

    epss: (
        ThreatIntelligenceRefreshStageResult
    )

    reprocessing: (
        ReevaluateThreatIntelligenceTargetsResult
    )

    @property
    def has_source_failures(
        self,
    ) -> bool:
        return any(
            (
                self.cisa_kev.failed,
                self.github_advisory.failed,
                self.epss.failed,
            )
        )

    @property
    def source_failure_count(
        self,
    ) -> int:
        return sum(
            (
                int(self.cisa_kev.failed),
                int(
                    self
                    .github_advisory
                    .failed
                ),
                int(self.epss.failed),
            )
        )


class ThreatIntelligenceSchedulerCycleService:
    """
    Cycle résilient multi-source.

    Une source externe en panne ne bloque pas
    les autres sources ni les réévaluations
    qui restent possibles.
    """

    def __init__(
        self,
        *,
        cisa_kev_stage: (
            ThreatIntelligenceRefreshStage
        ),
        github_advisory_stage: (
            ThreatIntelligenceRefreshStage
        ),
        epss_stage: (
            ThreatIntelligenceRefreshStage
        ),
        target_reevaluator: (
            ThreatIntelligenceTargetReevaluator
        ),
    ) -> None:
        if cisa_kev_stage is None:
            raise ValueError(
                "cisa_kev_stage must not be None"
            )

        if github_advisory_stage is None:
            raise ValueError(
                "github_advisory_stage "
                "must not be None"
            )

        if epss_stage is None:
            raise ValueError(
                "epss_stage must not be None"
            )

        if target_reevaluator is None:
            raise ValueError(
                "target_reevaluator "
                "must not be None"
            )

        self._cisa_kev_stage = (
            cisa_kev_stage
        )

        self._github_advisory_stage = (
            github_advisory_stage
        )

        self._epss_stage = (
            epss_stage
        )

        self._target_reevaluator = (
            target_reevaluator
        )

    def run(
        self,
        *,
        evaluated_at: datetime,
    ) -> ThreatIntelligenceSchedulerCycleResult:
        normalized_evaluated_at = (
            normalize_datetime_utc(
                evaluated_at,
                field_name="evaluated_at",
            )
        )

        cisa_result = (
            self._run_stage_resilient(
                stage=self._cisa_kev_stage,
                stage_name="CISA KEV",
            )
        )

        github_result = (
            self._run_stage_resilient(
                stage=(
                    self
                    ._github_advisory_stage
                ),
                stage_name=(
                    "GitHub Advisory"
                ),
            )
        )

        epss_result = (
            self._run_stage_resilient(
                stage=self._epss_stage,
                stage_name="EPSS",
            )
        )

        reprocessing_result = (
            self._target_reevaluator
            .reevaluate(
                cisa_kev_changed=(
                    cisa_result.succeeded
                    and cisa_result.changed
                ),
                github_advisory_changed=(
                    github_result.succeeded
                    and github_result.changed
                ),
                epss_changed=(
                    epss_result.succeeded
                    and epss_result.changed
                ),
                evaluated_at=(
                    normalized_evaluated_at
                ),
            )
        )

        return (
            ThreatIntelligenceSchedulerCycleResult(
                cisa_kev=cisa_result,
                github_advisory=(
                    github_result
                ),
                epss=epss_result,
                reprocessing=(
                    reprocessing_result
                ),
            )
        )

    @classmethod
    def _run_stage_resilient(
        cls,
        *,
        stage: ThreatIntelligenceRefreshStage,
        stage_name: str,
    ) -> ThreatIntelligenceRefreshStageResult:
        try:
            result = stage.run()

            cls._validate_success_result(
                result=result,
                stage_name=stage_name,
            )

            return result

        except Exception as error:
            return (
                cls._build_failed_result(
                    error=error
                )
            )

    @staticmethod
    def _validate_success_result(
        *,
        result: object,
        stage_name: str,
    ) -> None:
        if not isinstance(
            result,
            ThreatIntelligenceRefreshStageResult,
        ):
            raise RuntimeError(
                f"{stage_name} refresh stage "
                "returned an invalid result"
            )

        if (
            result.status
            != STAGE_STATUS_COMPLETED
        ):
            raise RuntimeError(
                f"{stage_name} refresh stage "
                "must return completed status "
                "when run() succeeds"
            )

        if not isinstance(
            result.changed,
            bool,
        ):
            raise RuntimeError(
                f"{stage_name} refresh stage "
                "returned an invalid changed flag"
            )

        if (
            isinstance(
                result.processed_count,
                bool,
            )
            or not isinstance(
                result.processed_count,
                int,
            )
            or result.processed_count < 0
        ):
            raise RuntimeError(
                f"{stage_name} refresh stage "
                "returned an invalid "
                "processed_count"
            )

        if not isinstance(
            result.metrics,
            ThreatIntelligenceStageMetrics,
        ):
            raise RuntimeError(
                f"{stage_name} refresh stage "
                "returned invalid metrics"
            )

        if result.error_type is not None:
            raise RuntimeError(
                f"{stage_name} completed result "
                "must not contain error_type"
            )

        if (
            result.error_summary
            is not None
        ):
            raise RuntimeError(
                f"{stage_name} completed result "
                "must not contain error_summary"
            )

    @staticmethod
    def _build_failed_result(
        *,
        error: Exception,
    ) -> ThreatIntelligenceRefreshStageResult:
        error_type = (
            type(error).__name__
        )

        message = str(
            error
        ).strip()

        raw_summary = (
            f"{error_type}: {message}"
            if message
            else error_type
        )

        sanitized_summary = (
            redact_sensitive_data(
                raw_summary,
                max_length=500,
            )
        )

        return (
            ThreatIntelligenceRefreshStageResult(
                changed=False,
                processed_count=0,
                status=(
                    STAGE_STATUS_FAILED
                ),
                error_type=error_type,
                error_summary=(
                    sanitized_summary
                ),
            )
        )