from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from application.services.cwe_enrichment_service import (
    CWEEnrichmentResult,
    CWEEnrichmentService,
)
from domain.threat import Threat


@dataclass(frozen=True)
class CWEEnrichmentJobResult:
    """
    Result exposed by the inbound CWE enrichment job.

    The application service result is preserved while the job adds
    execution-level information useful to an orchestrator, scheduler
    or command-line entrypoint.
    """

    enrichment_result: CWEEnrichmentResult

    @property
    def threats(
        self,
    ) -> list[Threat]:
        """
        Return the enriched Threat objects.
        """

        return self.enrichment_result.threats

    @property
    def metadata(
        self,
    ) -> dict[str, Any]:
        """
        Return enrichment execution metadata.
        """

        return self.enrichment_result.metadata


class CWEEnrichmentJob:
    """
    Inbound adapter responsible for orchestrating CWE enrichment.

    Responsibilities:
    - receive Threat objects from the application entrypoint;
    - delegate the enrichment logic to CWEEnrichmentService;
    - return enriched Threat objects and execution metadata.

    This adapter contains no CWE resolution or normalization logic.
    """

    def __init__(
        self,
        service: CWEEnrichmentService,
    ) -> None:
        if service is None:
            raise ValueError(
                "service is required."
            )

        if not isinstance(
            service,
            CWEEnrichmentService,
        ):
            raise TypeError(
                "service must be a CWEEnrichmentService instance."
            )

        self.service = service

    def run(
        self,
        threats: Iterable[Threat],
    ) -> CWEEnrichmentJobResult:
        """
        Enrich several Threat objects with official CWE entries.

        Threat objects are enriched in place by the application
        service and returned through CWEEnrichmentJobResult.
        """

        normalized_threats = self._validate_threats(
            threats
        )

        enrichment_result = (
            self.service.enrich_threats(
                normalized_threats
            )
        )

        return CWEEnrichmentJobResult(
            enrichment_result=enrichment_result
        )

    def run_single(
        self,
        threat: Threat,
    ) -> CWEEnrichmentJobResult:
        """
        Enrich one Threat object.
        """

        if not isinstance(
            threat,
            Threat,
        ):
            raise TypeError(
                "threat must be a Threat instance."
            )

        enrichment_result = (
            self.service.enrich_threat(
                threat
            )
        )

        return CWEEnrichmentJobResult(
            enrichment_result=enrichment_result
        )

    @staticmethod
    def _validate_threats(
        threats: Iterable[Threat],
    ) -> list[Threat]:
        """
        Validate and materialize the Threat collection.

        Materialization prevents generators from being consumed more
        than once during orchestration and produces predictable errors
        before invoking the application service.
        """

        if isinstance(
            threats,
            (str, bytes),
        ):
            raise TypeError(
                "threats must be an iterable of Threat objects."
            )

        try:
            normalized_threats = list(
                threats
            )

        except TypeError as error:
            raise TypeError(
                "threats must be an iterable of Threat objects."
            ) from error

        for threat in normalized_threats:
            if not isinstance(
                threat,
                Threat,
            ):
                raise TypeError(
                    "Every threats element must be "
                    "a Threat instance."
                )

        return normalized_threats