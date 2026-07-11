from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from time import perf_counter
from typing import Any, Dict, List, Optional, Sequence

from application.ports.inbound.threat_source import (
    ThreatSource,
)
from application.services.epss_enrichment_service import (
    EPSSEnrichmentResult,
    EPSSEnrichmentService,
)
from application.services.threat_correlation_service import (
    CorrelatedThreat,
    ThreatCorrelationResult,
    ThreatCorrelationService,
)
from domain.collection_result import CollectionResult
from domain.threat import Threat


# ============================================================
# Pipeline execution models
# ============================================================


@dataclass
class SourceExecutionResult:
    """
    Describes the execution of one threat intelligence source.

    A failed source does not necessarily stop the complete pipeline.
    The behavior depends on the fail_fast pipeline option.
    """

    source_name: str

    collection_result: Optional[CollectionResult] = None

    success: bool = False

    error_type: Optional[str] = None
    error_message: Optional[str] = None

    duration_seconds: float = 0.0

    @property
    def threats_count(self) -> int:
        """
        Return the number of Threat objects collected by this source.
        """

        if self.collection_result is None:
            return 0

        return len(
            self.collection_result.threats
        )


@dataclass
class ThreatIntelligencePipelineResult:
    """
    Complete result of a threat intelligence pipeline execution.

    This result preserves:

    - the individual execution status of every source;
    - the original CollectionResult returned by every successful source;
    - the correlation groups;
    - the EPSS enrichment result;
    - pipeline-level metadata and errors.

    No field-level fusion is performed.
    """

    source_executions: List[SourceExecutionResult] = field(
        default_factory=list
    )

    collection_results: List[CollectionResult] = field(
        default_factory=list
    )

    correlation_result: ThreatCorrelationResult = field(
        default_factory=ThreatCorrelationResult
    )

    epss_enrichment_result: Optional[
        EPSSEnrichmentResult
    ] = None

    metadata: Dict[str, Any] = field(
        default_factory=dict
    )

    errors: List[Dict[str, str]] = field(
        default_factory=list
    )

    # --------------------------------------------------------
    # Result helper methods
    # --------------------------------------------------------

    def all_threats(self) -> List[Threat]:
        """
        Return every source-specific Threat object from all groups.

        Several Threat objects may have the same CVE ID because
        source-specific records are intentionally preserved.
        """

        threats: List[Threat] = []

        for group in self.correlation_result.all_groups():
            threats.extend(
                group.threats
            )

        return threats

    def unique_ids(self) -> List[str]:
        """
        Return all unique correlated vulnerability identifiers.
        """

        return self.correlation_result.unique_ids()

    def get_group(
        self,
        threat_id: str,
    ) -> Optional[CorrelatedThreat]:
        """
        Return the correlation group associated with an identifier.
        """

        return self.correlation_result.groups.get(
            threat_id
        )

    def multi_source_groups(
        self,
    ) -> List[CorrelatedThreat]:
        """
        Return vulnerabilities reported by more than one source.
        """

        return (
            self.correlation_result.multi_source_groups()
        )

    def successful_sources(self) -> List[str]:
        """
        Return the names of successfully executed sources.
        """

        return [
            execution.source_name
            for execution in self.source_executions
            if execution.success
        ]

    def failed_sources(self) -> List[str]:
        """
        Return the names of failed sources.
        """

        return [
            execution.source_name
            for execution in self.source_executions
            if not execution.success
        ]


# ============================================================
# Pipeline service
# ============================================================


class ThreatIntelligencePipelineService:
    """
    Application service orchestrating the complete threat
    intelligence collection pipeline.

    Pipeline stages:

    1. Execute all configured ThreatSource implementations.
    2. Preserve each source's CollectionResult.
    3. Correlate Threat objects by identifier.
    4. Preserve all source-specific records without fusion.
    5. Enrich all CVE-based Threat objects with EPSS.
    6. Return a detailed pipeline result.

    This service does not know how individual sources communicate
    with their providers. It only depends on the ThreatSource port.
    """

    def __init__(
        self,
        sources: Sequence[ThreatSource],
        correlation_service: Optional[
            ThreatCorrelationService
        ] = None,
        epss_enrichment_service: Optional[
            EPSSEnrichmentService
        ] = None,
        fail_fast: bool = False,
    ) -> None:
        """
        Args:
            sources:
                Threat intelligence sources participating in the
                pipeline.

            correlation_service:
                Optional correlation service dependency. A default
                instance is created when omitted.

            epss_enrichment_service:
                Optional EPSS enrichment dependency. A default
                instance is created when omitted.

            fail_fast:
                When True, the first source or EPSS error stops the
                pipeline and is re-raised.

                When False, failed sources are recorded and the
                pipeline continues with the available sources.
        """

        self.sources = list(
            sources
        )

        self.correlation_service = (
            correlation_service
            or ThreatCorrelationService()
        )

        self.epss_enrichment_service = (
            epss_enrichment_service
            or EPSSEnrichmentService()
        )

        self.fail_fast = fail_fast

    def run(
        self,
        epss_date: Optional[str] = None,
        enrich_with_epss: bool = True,
    ) -> ThreatIntelligencePipelineResult:
        """
        Execute the complete threat intelligence pipeline.

        Args:
            epss_date:
                Optional historical EPSS date in YYYY-MM-DD format.

            enrich_with_epss:
                When False, collection and correlation are executed
                but the EPSS stage is skipped.

        Returns:
            ThreatIntelligencePipelineResult containing all
            source-specific records, correlation groups, enrichment
            metadata and pipeline execution information.
        """

        pipeline_started_at = datetime.now(
            UTC
        )

        pipeline_timer = perf_counter()

        source_executions = (
            self._collect_sources()
        )

        collection_results = [
            execution.collection_result
            for execution in source_executions
            if (
                execution.success
                and execution.collection_result is not None
            )
        ]

        errors = self._build_source_errors(
            source_executions
        )

        correlation_started = perf_counter()

        correlation_result = (
            self.correlation_service.correlate_results(
                collection_results
            )
        )

        correlation_duration = (
            perf_counter()
            - correlation_started
        )

        epss_result: Optional[
            EPSSEnrichmentResult
        ] = None

        epss_duration = 0.0
        epss_error: Optional[Dict[str, str]] = None

        if enrich_with_epss:
            epss_started = perf_counter()

            try:
                epss_result = (
                    self.epss_enrichment_service
                    .enrich_correlation_result(
                        correlation_result=correlation_result,
                        date=epss_date,
                    )
                )

            except Exception as error:
                epss_error = {
                    "stage": "EPSS",
                    "error_type": type(error).__name__,
                    "error_message": str(error),
                }

                errors.append(
                    epss_error
                )

                if self.fail_fast:
                    raise

            finally:
                epss_duration = (
                    perf_counter()
                    - epss_started
                )

        finished_at = datetime.now(
            UTC
        )

        total_duration = (
            perf_counter()
            - pipeline_timer
        )

        metadata = self._build_pipeline_metadata(
            source_executions=source_executions,
            collection_results=collection_results,
            correlation_result=correlation_result,
            epss_result=epss_result,
            epss_error=epss_error,
            enrich_with_epss=enrich_with_epss,
            epss_date=epss_date,
            started_at=pipeline_started_at,
            finished_at=finished_at,
            total_duration=total_duration,
            correlation_duration=correlation_duration,
            epss_duration=epss_duration,
        )

        return ThreatIntelligencePipelineResult(
            source_executions=source_executions,
            collection_results=collection_results,
            correlation_result=correlation_result,
            epss_enrichment_result=epss_result,
            metadata=metadata,
            errors=errors,
        )

    # ========================================================
    # Collection stage
    # ========================================================

    def _collect_sources(
        self,
    ) -> List[SourceExecutionResult]:
        """
        Execute each configured source independently.
        """

        executions: List[
            SourceExecutionResult
        ] = []

        for source in self.sources:
            execution = self._collect_source(
                source
            )

            executions.append(
                execution
            )

        return executions

    def _collect_source(
        self,
        source: ThreatSource,
    ) -> SourceExecutionResult:
        """
        Execute one ThreatSource and capture its result or error.
        """

        source_name = self._safe_source_name(
            source
        )

        started = perf_counter()

        try:
            collection_result = source.collect()

            if not isinstance(
                collection_result,
                CollectionResult,
            ):
                raise TypeError(
                    f"Source {source_name} returned "
                    f"{type(collection_result).__name__}; "
                    "CollectionResult was expected."
                )

            # Guarantee that correlation can identify the source,
            # even if a source forgot to add its name to metadata.
            collection_result.metadata.setdefault(
                "source",
                source_name,
            )

            return SourceExecutionResult(
                source_name=source_name,
                collection_result=collection_result,
                success=True,
                duration_seconds=(
                    perf_counter()
                    - started
                ),
            )

        except Exception as error:
            execution = SourceExecutionResult(
                source_name=source_name,
                success=False,
                error_type=type(error).__name__,
                error_message=str(error),
                duration_seconds=(
                    perf_counter()
                    - started
                ),
            )

            if self.fail_fast:
                raise

            return execution

    def _safe_source_name(
        self,
        source: ThreatSource,
    ) -> str:
        """
        Read a source name without allowing a broken name method
        to prevent error reporting.
        """

        try:
            name = source.name()

            if isinstance(name, str) and name.strip():
                return name.strip()

        except Exception:
            pass

        return type(source).__name__

    # ========================================================
    # Metadata and error helpers
    # ========================================================

    def _build_source_errors(
        self,
        executions: List[SourceExecutionResult],
    ) -> List[Dict[str, str]]:
        """
        Build normalized error entries for failed sources.
        """

        errors: List[Dict[str, str]] = []

        for execution in executions:
            if execution.success:
                continue

            errors.append(
                {
                    "stage": "COLLECTION",
                    "source": execution.source_name,
                    "error_type": (
                        execution.error_type
                        or "UnknownError"
                    ),
                    "error_message": (
                        execution.error_message
                        or "Unknown source collection error."
                    ),
                }
            )

        return errors

    def _build_pipeline_metadata(
        self,
        *,
        source_executions: List[
            SourceExecutionResult
        ],
        collection_results: List[
            CollectionResult
        ],
        correlation_result: ThreatCorrelationResult,
        epss_result: Optional[
            EPSSEnrichmentResult
        ],
        epss_error: Optional[
            Dict[str, str]
        ],
        enrich_with_epss: bool,
        epss_date: Optional[str],
        started_at: datetime,
        finished_at: datetime,
        total_duration: float,
        correlation_duration: float,
        epss_duration: float,
    ) -> Dict[str, Any]:
        """
        Build global pipeline execution metadata.
        """

        successful_executions = [
            execution
            for execution in source_executions
            if execution.success
        ]

        failed_executions = [
            execution
            for execution in source_executions
            if not execution.success
        ]

        source_summaries = [
            {
                "source": execution.source_name,
                "success": execution.success,
                "threats": execution.threats_count,
                "duration_seconds": round(
                    execution.duration_seconds,
                    6,
                ),
                "error_type": execution.error_type,
                "error_message": execution.error_message,
            }
            for execution in source_executions
        ]

        total_source_records = sum(
            len(result.threats)
            for result in collection_results
        )

        epss_metadata = (
            epss_result.metadata
            if epss_result is not None
            else None
        )

        if not enrich_with_epss:
            epss_status = "SKIPPED"

        elif epss_error is not None:
            epss_status = "FAILED"

        else:
            epss_status = "SUCCESS"

        pipeline_status = self._determine_pipeline_status(
            successful_sources=len(
                successful_executions
            ),
            failed_sources=len(
                failed_executions
            ),
            epss_status=epss_status,
        )

        return {
            "pipeline": "THREAT_INTELLIGENCE",
            "status": pipeline_status,
            "started_at": started_at.isoformat(),
            "finished_at": finished_at.isoformat(),
            "duration_seconds": round(
                total_duration,
                6,
            ),

            "configured_sources": len(
                source_executions
            ),
            "successful_sources": len(
                successful_executions
            ),
            "failed_sources": len(
                failed_executions
            ),
            "source_summaries": source_summaries,

            "total_source_records": (
                total_source_records
            ),
            "unique_threats": (
                correlation_result.metadata.get(
                    "unique_threats",
                    0,
                )
            ),
            "multi_source_threats": (
                correlation_result.metadata.get(
                    "multi_source_threats",
                    0,
                )
            ),

            "correlation_duration_seconds": round(
                correlation_duration,
                6,
            ),

            "epss_enabled": enrich_with_epss,
            "epss_status": epss_status,
            "epss_date_requested": epss_date,
            "epss_duration_seconds": round(
                epss_duration,
                6,
            ),
            "epss_metadata": epss_metadata,

            "fusion_performed": False,
            "source_specific_records_preserved": True,
        }

    def _determine_pipeline_status(
        self,
        *,
        successful_sources: int,
        failed_sources: int,
        epss_status: str,
    ) -> str:
        """
        Determine the global pipeline status.
        """

        if successful_sources == 0:
            return "FAILED"

        if failed_sources > 0:
            return "PARTIAL_SUCCESS"

        if epss_status == "FAILED":
            return "PARTIAL_SUCCESS"

        return "SUCCESS"
