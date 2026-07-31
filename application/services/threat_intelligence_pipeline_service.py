from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from time import perf_counter
from typing import Any, Sequence

from application.ports.inbound.threat_source import (
    ThreatSource,
)
from application.security.operational_error_sanitizer import (
    sanitize_exception_message,
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
    Résultat de l'exécution d'une source de renseignement.

    Une source en échec n'arrête pas nécessairement le pipeline.
    Le comportement dépend de l'option fail_fast.
    """

    source_name: str

    collection_result: CollectionResult | None = None

    success: bool = False

    error_type: str | None = None
    error_message: str | None = None

    duration_seconds: float = 0.0

    @property
    def threats_count(
        self,
    ) -> int:
        """
        Retourne le nombre de Threat collectés par la source.
        """
        if self.collection_result is None:
            return 0

        return len(
            self.collection_result.threats
        )


@dataclass
class ThreatIntelligencePipelineResult:
    """
    Résultat complet du pipeline de threat intelligence.

    Les enregistrements propres à chaque source sont préservés.
    Aucune fusion destructive des champs n'est effectuée.
    """

    source_executions: list[
        SourceExecutionResult
    ] = field(
        default_factory=list
    )

    collection_results: list[
        CollectionResult
    ] = field(
        default_factory=list
    )

    correlation_result: ThreatCorrelationResult = field(
        default_factory=ThreatCorrelationResult
    )

    epss_enrichment_result: (
        EPSSEnrichmentResult | None
    ) = None

    metadata: dict[str, Any] = field(
        default_factory=dict
    )

    errors: list[
        dict[str, str]
    ] = field(
        default_factory=list
    )

    def all_threats(
        self,
    ) -> list[Threat]:
        """
        Retourne tous les objets Threat préservés dans les groupes.
        """
        threats: list[Threat] = []

        for group in (
            self.correlation_result.all_groups()
        ):
            threats.extend(
                group.threats
            )

        return threats

    def unique_ids(
        self,
    ) -> list[str]:
        """
        Retourne les identifiants uniques corrélés.
        """
        return (
            self.correlation_result.unique_ids()
        )

    def get_group(
        self,
        threat_id: str,
    ) -> CorrelatedThreat | None:
        """
        Retourne le groupe associé à un identifiant.
        """
        return (
            self.correlation_result.groups.get(
                threat_id
            )
        )

    def multi_source_groups(
        self,
    ) -> list[CorrelatedThreat]:
        """
        Retourne les groupes présents dans plusieurs sources.
        """
        return (
            self.correlation_result
            .multi_source_groups()
        )

    def successful_sources(
        self,
    ) -> list[str]:
        """
        Retourne les noms des sources exécutées avec succès.
        """
        return [
            execution.source_name
            for execution in self.source_executions
            if execution.success
        ]

    def failed_sources(
        self,
    ) -> list[str]:
        """
        Retourne les noms des sources en échec.
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
    Orchestre la collecte, la corrélation et l'enrichissement.

    Étapes :

    1. Exécuter les sources configurées.
    2. Préserver leurs CollectionResult.
    3. Corréler les Threat par identifiant.
    4. Préserver les objets propres à chaque source.
    5. Enrichir localement les CVE avec EPSS.
    6. Retourner un résultat structuré.

    Le service ne construit aucune dépendance infrastructurelle.
    Le service EPSS doit être injecté explicitement.
    """

    def __init__(
        self,
        sources: Sequence[ThreatSource],
        correlation_service: (
            ThreatCorrelationService | None
        ) = None,
        epss_enrichment_service: (
            EPSSEnrichmentService | None
        ) = None,
        fail_fast: bool = False,
    ) -> None:
        """
        Args:
            sources:
                Sources participant au pipeline.

            correlation_service:
                Service de corrélation optionnel. Une implémentation
                par défaut est créée lorsqu'il est absent.

            epss_enrichment_service:
                Service d'enrichissement EPSS optionnel.

                Il doit être fourni lorsque l'enrichissement EPSS
                est activé.

                Le pipeline ne construit jamais lui-même une
                dépendance PostgreSQL.

            fail_fast:
                Lorsque True, la première erreur est propagée.

                Lorsque False, les erreurs sont assainies et
                enregistrées dans le résultat.
        """
        self.sources = list(
            sources
        )

        self.correlation_service = (
            correlation_service
            if correlation_service is not None
            else ThreatCorrelationService()
        )

        self.epss_enrichment_service = (
            epss_enrichment_service
        )

        self.fail_fast = fail_fast

    def run(
        self,
        epss_date: str | None = None,
        enrich_with_epss: bool = True,
    ) -> ThreatIntelligencePipelineResult:
        """
        Exécute le pipeline complet.

        La dépendance EPSS est validée avant toute collecte externe.
        """
        epss_service = (
            self._require_epss_enrichment_service()
            if enrich_with_epss
            else None
        )

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
                and execution.collection_result
                is not None
            )
        ]

        errors = self._build_source_errors(
            source_executions
        )

        correlation_started = perf_counter()

        correlation_result = (
            self.correlation_service
            .correlate_results(
                collection_results
            )
        )

        correlation_duration = (
            perf_counter()
            - correlation_started
        )

        epss_result: (
            EPSSEnrichmentResult | None
        ) = None

        epss_error: (
            dict[str, str] | None
        ) = None

        epss_duration = 0.0

        if epss_service is not None:
            epss_started = perf_counter()

            try:
                epss_result = (
                    epss_service
                    .enrich_correlation_result(
                        correlation_result=(
                            correlation_result
                        ),
                        date=epss_date,
                    )
                )

            except Exception as error:
                epss_error = {
                    "stage": "EPSS",
                    "error_type": (
                        type(error).__name__
                    ),
                    "error_message": (
                        sanitize_exception_message(
                            error
                        )
                    ),
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

        metadata = (
            self._build_pipeline_metadata(
                source_executions=(
                    source_executions
                ),
                collection_results=(
                    collection_results
                ),
                correlation_result=(
                    correlation_result
                ),
                epss_result=epss_result,
                epss_error=epss_error,
                enrich_with_epss=(
                    enrich_with_epss
                ),
                epss_date=epss_date,
                started_at=(
                    pipeline_started_at
                ),
                finished_at=finished_at,
                total_duration=(
                    total_duration
                ),
                correlation_duration=(
                    correlation_duration
                ),
                epss_duration=(
                    epss_duration
                ),
            )
        )

        return ThreatIntelligencePipelineResult(
            source_executions=(
                source_executions
            ),
            collection_results=(
                collection_results
            ),
            correlation_result=(
                correlation_result
            ),
            epss_enrichment_result=(
                epss_result
            ),
            metadata=metadata,
            errors=errors,
        )

    def _require_epss_enrichment_service(
        self,
    ) -> EPSSEnrichmentService:
        """
        Retourne la dépendance EPSS injectée.

        Cette validation est exécutée avant toute collecte afin
        d'empêcher un pipeline partiellement exécuté.
        """
        if (
            self.epss_enrichment_service
            is None
        ):
            raise RuntimeError(
                "epss_enrichment_service is required "
                "when EPSS enrichment is enabled"
            )

        return (
            self.epss_enrichment_service
        )

    # ========================================================
    # Collection
    # ========================================================

    def _collect_sources(
        self,
    ) -> list[SourceExecutionResult]:
        """
        Exécute chaque source indépendamment.
        """
        executions: list[
            SourceExecutionResult
        ] = []

        for source in self.sources:
            executions.append(
                self._collect_source(
                    source
                )
            )

        return executions

    def _collect_source(
        self,
        source: ThreatSource,
    ) -> SourceExecutionResult:
        """
        Exécute une source et capture son résultat ou son erreur.
        """
        source_name = (
            self._safe_source_name(
                source
            )
        )

        started = perf_counter()

        try:
            collection_result = (
                source.collect()
            )

            if not isinstance(
                collection_result,
                CollectionResult,
            ):
                raise TypeError(
                    f"Source {source_name} returned "
                    f"{type(collection_result).__name__}; "
                    "CollectionResult was expected."
                )

            collection_result.metadata.setdefault(
                "source",
                source_name,
            )

            return SourceExecutionResult(
                source_name=source_name,
                collection_result=(
                    collection_result
                ),
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
                error_type=(
                    type(error).__name__
                ),
                error_message=(
                    sanitize_exception_message(
                        error
                    )
                ),
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
        Lit le nom de la source sans laisser une méthode name()
        défectueuse empêcher la création du rapport d'erreur.
        """
        try:
            name = source.name()

            if (
                isinstance(name, str)
                and name.strip()
            ):
                return name.strip()

        except Exception:
            pass

        return type(source).__name__

    # ========================================================
    # Metadata and errors
    # ========================================================

    def _build_source_errors(
        self,
        executions: list[
            SourceExecutionResult
        ],
    ) -> list[dict[str, str]]:
        """
        Construit les erreurs structurées des sources.
        """
        errors: list[
            dict[str, str]
        ] = []

        for execution in executions:
            if execution.success:
                continue

            errors.append(
                {
                    "stage": "COLLECTION",
                    "source": (
                        execution.source_name
                    ),
                    "error_type": (
                        execution.error_type
                        or "UnknownError"
                    ),
                    "error_message": (
                        execution.error_message
                        or (
                            "Unknown source "
                            "collection error."
                        )
                    ),
                }
            )

        return errors

    def _build_pipeline_metadata(
        self,
        *,
        source_executions: list[
            SourceExecutionResult
        ],
        collection_results: list[
            CollectionResult
        ],
        correlation_result: (
            ThreatCorrelationResult
        ),
        epss_result: (
            EPSSEnrichmentResult | None
        ),
        epss_error: (
            dict[str, str] | None
        ),
        enrich_with_epss: bool,
        epss_date: str | None,
        started_at: datetime,
        finished_at: datetime,
        total_duration: float,
        correlation_duration: float,
        epss_duration: float,
    ) -> dict[str, Any]:
        """
        Construit les métadonnées globales du pipeline.
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
                "source": (
                    execution.source_name
                ),
                "success": (
                    execution.success
                ),
                "threats": (
                    execution.threats_count
                ),
                "duration_seconds": round(
                    execution.duration_seconds,
                    6,
                ),
                "error_type": (
                    execution.error_type
                ),
                "error_message": (
                    execution.error_message
                ),
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

        pipeline_status = (
            self._determine_pipeline_status(
                successful_sources=len(
                    successful_executions
                ),
                failed_sources=len(
                    failed_executions
                ),
                epss_status=epss_status,
            )
        )

        return {
            "pipeline": (
                "THREAT_INTELLIGENCE"
            ),
            "status": pipeline_status,
            "started_at": (
                started_at.isoformat()
            ),
            "finished_at": (
                finished_at.isoformat()
            ),
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
            "source_summaries": (
                source_summaries
            ),
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
            "epss_enabled": (
                enrich_with_epss
            ),
            "epss_status": (
                epss_status
            ),
            "epss_date_requested": (
                epss_date
            ),
            "epss_duration_seconds": round(
                epss_duration,
                6,
            ),
            "epss_metadata": (
                epss_metadata
            ),
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
        Détermine le statut global du pipeline.
        """
        if successful_sources == 0:
            return "FAILED"

        if failed_sources > 0:
            return "PARTIAL_SUCCESS"

        if epss_status == "FAILED":
            return "PARTIAL_SUCCESS"

        return "SUCCESS"