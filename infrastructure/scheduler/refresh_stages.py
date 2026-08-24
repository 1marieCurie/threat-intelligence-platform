from __future__ import annotations

import logging
import time
from collections.abc import (
    Callable,
    Iterable,
)
from typing import Protocol

import requests

from application.services.threat_intelligence_scheduler_cycle_service import (
    ThreatIntelligenceRefreshStageResult,
    ThreatIntelligenceStageMetrics,
)
from infrastructure.adapters.outbound.github_advisory_connector import (
    GitHubAdvisoryConnectorError,
)


logger = logging.getLogger(__name__)


class JobWithoutArguments(
    Protocol
):
    def run(
        self,
    ) -> object:
        ...


class EPSSSynchronizationRunner(
    Protocol
):
    def run(
        self,
        cve_ids: Iterable[str],
    ) -> object:
        ...


class CanonicalCVEPageReader(
    Protocol
):
    def read_batch(
        self,
        *,
        after_cve_id: str | None,
        limit: int,
    ) -> tuple[
        str,
        ...,
    ]:
        ...


class CisaKevRefreshStage:
    """
    Refresh complet CISA KEV :

        ingestion
            ↓
        normalisation
            ↓
        canonicalisation

    CISA KEV reste traité comme un snapshot complet car
    son volume reste raisonnable pour la démonstration.

    Important :

    La canonicalisation CISA reparcourt actuellement le
    snapshot complet. Un canonical_updated > 0 ne signifie
    donc pas nécessairement que le fournisseur a changé.

    Le flag changed est volontairement basé uniquement sur
    l'arrivée ou la normalisation de nouvelles données.
    """

    def __init__(
        self,
        *,
        ingestion_job: JobWithoutArguments,
        normalization_job: JobWithoutArguments,
        canonical_job: JobWithoutArguments,
    ) -> None:
        if ingestion_job is None:
            raise ValueError(
                "ingestion_job must not be None"
            )

        if normalization_job is None:
            raise ValueError(
                "normalization_job must not be None"
            )

        if canonical_job is None:
            raise ValueError(
                "canonical_job must not be None"
            )

        self._ingestion_job = (
            ingestion_job
        )

        self._normalization_job = (
            normalization_job
        )

        self._canonical_job = (
            canonical_job
        )

    def run(
        self,
    ) -> ThreatIntelligenceRefreshStageResult:
        ingestion_result = (
            self._ingestion_job.run()
        )

        pagination_complete = (
            self._read_boolean(
                ingestion_result,
                "pagination_complete",
                stage_name="CISA KEV ingestion",
            )
        )

        if not pagination_complete:
            raise RuntimeError(
                "CISA KEV ingestion did not "
                "return a complete snapshot"
            )

        records_received = (
            self._read_optional_non_negative_integer(
                ingestion_result,
                "records_received",
                default=0,
            )
        )

        records_persisted = (
            self._read_non_negative_integer(
                ingestion_result,
                "records_persisted",
                stage_name="CISA KEV ingestion",
            )
        )

        normalization_result = (
            self._normalization_job.run()
        )

        claimed = (
            self._read_non_negative_integer(
                normalization_result,
                "claimed",
                stage_name=(
                    "CISA KEV normalization"
                ),
            )
        )

        normalized = (
            self._read_optional_non_negative_integer(
                normalization_result,
                "normalized",
                default=0,
            )
        )

        already_normalized = (
            self._read_optional_non_negative_integer(
                normalization_result,
                "already_normalized",
                default=0,
            )
        )

        normalization_failed = (
            self._read_optional_non_negative_integer(
                normalization_result,
                "failed",
                default=0,
            )
        )

        canonical_result = (
            self._canonical_job.run()
        )

        canonical_records_read = (
            self._validate_canonical_result(
                canonical_result,
                stage_name=(
                    "CISA KEV canonical "
                    "correlation"
                ),
            )
        )

        canonical_created = (
            self._read_optional_non_negative_integer(
                canonical_result,
                "canonical_created",
                default=0,
            )
        )

        canonical_updated = (
            self._read_optional_non_negative_integer(
                canonical_result,
                "canonical_updated",
                default=0,
            )
        )

        canonical_persisted = (
            self._read_optional_non_negative_integer(
                canonical_result,
                "canonical_persisted",
                default=0,
            )
        )

        # CISA canonical parcourt le snapshot complet.
        #
        # canonical_updated peut donc être élevé même lorsque
        # le fournisseur n'a envoyé aucune nouvelle donnée.
        #
        # Ne pas utiliser les compteurs canoniques pour le
        # flag changed évite des réévaluations machines
        # inutiles à chaque cycle.
        changed = (
            records_persisted > 0
            or normalized > 0
        )

        metrics = (
            ThreatIntelligenceStageMetrics(
                pages_processed=1,
                records_received=(
                    records_received
                ),
                records_persisted=(
                    records_persisted
                ),
                normalization_claimed=(
                    claimed
                ),
                normalized=(
                    normalized
                ),
                already_normalized=(
                    already_normalized
                ),
                normalization_failed=(
                    normalization_failed
                ),
                canonical_records_read=(
                    canonical_records_read
                ),
                canonical_created=(
                    canonical_created
                ),
                canonical_updated=(
                    canonical_updated
                ),
                canonical_persisted=(
                    canonical_persisted
                ),
                limit_reached=False,
            )
        )

        return (
            ThreatIntelligenceRefreshStageResult(
                changed=changed,
                processed_count=(
                    canonical_records_read
                ),
                metrics=metrics,
            )
        )

    @staticmethod
    def _read_boolean(
        result: object,
        field_name: str,
        *,
        stage_name: str,
    ) -> bool:
        value = getattr(
            result,
            field_name,
            None,
        )

        if not isinstance(
            value,
            bool,
        ):
            raise RuntimeError(
                f"{stage_name} returned an "
                f"invalid {field_name}"
            )

        return value

    @staticmethod
    def _read_non_negative_integer(
        result: object,
        field_name: str,
        *,
        stage_name: str,
    ) -> int:
        value = getattr(
            result,
            field_name,
            None,
        )

        if (
            isinstance(
                value,
                bool,
            )
            or not isinstance(
                value,
                int,
            )
            or value < 0
        ):
            raise RuntimeError(
                f"{stage_name} returned an "
                f"invalid {field_name}"
            )

        return value

    @staticmethod
    def _read_optional_non_negative_integer(
        result: object,
        field_name: str,
        *,
        default: int,
    ) -> int:
        value = getattr(
            result,
            field_name,
            default,
        )

        if (
            isinstance(
                value,
                bool,
            )
            or not isinstance(
                value,
                int,
            )
            or value < 0
        ):
            raise RuntimeError(
                f"Invalid {field_name}"
            )

        return value

    @classmethod
    def _validate_canonical_result(
        cls,
        result: object,
        *,
        stage_name: str,
    ) -> int:
        source_exhausted = getattr(
            result,
            "source_exhausted",
            None,
        )

        max_batches_reached = getattr(
            result,
            "max_batches_reached",
            None,
        )

        if not isinstance(
            source_exhausted,
            bool,
        ):
            raise RuntimeError(
                f"{stage_name} returned an "
                "invalid source_exhausted"
            )

        if not isinstance(
            max_batches_reached,
            bool,
        ):
            raise RuntimeError(
                f"{stage_name} returned an "
                "invalid max_batches_reached"
            )

        if (
            not source_exhausted
            or max_batches_reached
        ):
            raise RuntimeError(
                f"{stage_name} did not "
                "complete"
            )

        return (
            cls._read_non_negative_integer(
                result,
                "records_read",
                stage_name=stage_name,
            )
        )


class GitHubAdvisoryRefreshStage:
    """
    Refresh GitHub Advisory borné.

    max_pages :
        garde-fou technique absolu.

    cycle_page_budget :
        nombre volontaire de pages que ce cycle
        est autorisé à ingérer.

    Quand cycle_page_budget est atteint :

        PAS D'ERREUR

        données déjà persistées
            ↓
        normalisation
            ↓
        canonicalisation incrémentale
            ↓
        résultat completed / limit_reached=True

    Le prochain cycle reprend au curseur durable
    déjà stocké dans ops.sync_state.

    Contrairement à CISA, la canonicalisation GitHub utilisée
    par le scheduler est désormais incrémentale. Un
    canonical_created/canonical_updated représente donc ici
    un changement réel à prendre en compte.
    """

    DEFAULT_MAX_PAGES = 100
    MAX_ALLOWED_PAGES = 1_000

    DEFAULT_RETRY_DELAYS_SECONDS = (
        2.0,
        5.0,
        10.0,
    )

    MAX_RETRY_DELAY_SECONDS = 30.0

    def __init__(
        self,
        *,
        ingestion_job: JobWithoutArguments,
        normalization_job: JobWithoutArguments,
        canonical_job: JobWithoutArguments,
        max_pages: int = DEFAULT_MAX_PAGES,
        cycle_page_budget: int | None = None,
        retry_delays_seconds: tuple[
            float,
            ...,
        ] = DEFAULT_RETRY_DELAYS_SECONDS,
        sleeper: Callable[
            [float],
            None,
        ] = time.sleep,
    ) -> None:
        if ingestion_job is None:
            raise ValueError(
                "ingestion_job must not be None"
            )

        if normalization_job is None:
            raise ValueError(
                "normalization_job must not be None"
            )

        if canonical_job is None:
            raise ValueError(
                "canonical_job must not be None"
            )

        self._validate_max_pages(
            max_pages
        )

        self._validate_cycle_page_budget(
            cycle_page_budget,
            max_pages=max_pages,
        )

        self._validate_retry_delays(
            retry_delays_seconds
        )

        if not callable(
            sleeper
        ):
            raise TypeError(
                "sleeper must be callable"
            )

        self._ingestion_job = (
            ingestion_job
        )

        self._normalization_job = (
            normalization_job
        )

        self._canonical_job = (
            canonical_job
        )

        self._max_pages = (
            max_pages
        )

        self._cycle_page_budget = (
            cycle_page_budget
        )

        self._retry_delays_seconds = (
            retry_delays_seconds
        )

        self._sleeper = sleeper

    def run(
        self,
    ) -> ThreatIntelligenceRefreshStageResult:
        total_received = 0
        total_persisted = 0
        pages_processed = 0

        pagination_complete = False
        limit_reached = False

        page_limit = (
            self._cycle_page_budget
            if (
                self._cycle_page_budget
                is not None
            )
            else self._max_pages
        )

        for _ in range(
            page_limit
        ):
            result = (
                self
                ._run_ingestion_page_with_retry()
            )

            pages_processed += 1

            received = (
                CisaKevRefreshStage
                ._read_optional_non_negative_integer(
                    result,
                    "records_received",
                    default=0,
                )
            )

            persisted = (
                CisaKevRefreshStage
                ._read_non_negative_integer(
                    result,
                    "records_persisted",
                    stage_name=(
                        "GitHub Advisory ingestion"
                    ),
                )
            )

            total_received += (
                received
            )

            total_persisted += (
                persisted
            )

            pagination_complete = (
                CisaKevRefreshStage
                ._read_boolean(
                    result,
                    "pagination_complete",
                    stage_name=(
                        "GitHub Advisory ingestion"
                    ),
                )
            )

            if pagination_complete:
                break

        if not pagination_complete:
            if (
                self._cycle_page_budget
                is not None
                and pages_processed
                >= self._cycle_page_budget
            ):
                limit_reached = True

            else:
                raise RuntimeError(
                    "GitHub Advisory ingestion "
                    "reached max_pages before "
                    "pagination completed"
                )

        normalization_result = (
            self._normalization_job.run()
        )

        claimed = (
            CisaKevRefreshStage
            ._read_non_negative_integer(
                normalization_result,
                "claimed",
                stage_name=(
                    "GitHub Advisory "
                    "normalization"
                ),
            )
        )

        normalized = (
            CisaKevRefreshStage
            ._read_optional_non_negative_integer(
                normalization_result,
                "normalized",
                default=0,
            )
        )

        already_normalized = (
            CisaKevRefreshStage
            ._read_optional_non_negative_integer(
                normalization_result,
                "already_normalized",
                default=0,
            )
        )

        normalization_failed = (
            CisaKevRefreshStage
            ._read_optional_non_negative_integer(
                normalization_result,
                "failed",
                default=0,
            )
        )

        canonical_result = (
            self._canonical_job.run()
        )

        canonical_records_read = (
            CisaKevRefreshStage
            ._validate_canonical_result(
                canonical_result,
                stage_name=(
                    "GitHub Advisory canonical "
                    "correlation"
                ),
            )
        )

        canonical_created = (
            CisaKevRefreshStage
            ._read_optional_non_negative_integer(
                canonical_result,
                "canonical_created",
                default=0,
            )
        )

        canonical_updated = (
            CisaKevRefreshStage
            ._read_optional_non_negative_integer(
                canonical_result,
                "canonical_updated",
                default=0,
            )
        )

        canonical_persisted = (
            CisaKevRefreshStage
            ._read_optional_non_negative_integer(
                canonical_result,
                "canonical_persisted",
                default=0,
            )
        )

        # Pour GitHub, le scheduler utilise un reader canonical
        # incrémental.
        #
        # canonical_created / canonical_updated correspondent
        # donc à des advisories réellement nouveaux ou dont la
        # version normalisée n'avait pas encore été propagée.
        #
        # Cela couvre également le rattrapage après un ancien
        # cycle partiel :
        #
        # raw déjà persisté
        # normalization déjà terminée
        # canonicalisation précédemment interrompue
        #          ↓
        # nouveau cycle
        #          ↓
        # canonical_updated > 0
        #          ↓
        # changed=True
        #          ↓
        # réévaluation machine nécessaire
        changed = (
            total_persisted > 0
            or normalized > 0
            or canonical_created > 0
            or canonical_updated > 0
        )

        metrics = (
            ThreatIntelligenceStageMetrics(
                pages_processed=(
                    pages_processed
                ),
                records_received=(
                    total_received
                ),
                records_persisted=(
                    total_persisted
                ),
                normalization_claimed=(
                    claimed
                ),
                normalized=(
                    normalized
                ),
                already_normalized=(
                    already_normalized
                ),
                normalization_failed=(
                    normalization_failed
                ),
                canonical_records_read=(
                    canonical_records_read
                ),
                canonical_created=(
                    canonical_created
                ),
                canonical_updated=(
                    canonical_updated
                ),
                canonical_persisted=(
                    canonical_persisted
                ),
                limit_reached=(
                    limit_reached
                ),
            )
        )

        return (
            ThreatIntelligenceRefreshStageResult(
                changed=changed,
                processed_count=(
                    canonical_records_read
                ),
                metrics=metrics,
            )
        )

    def _run_ingestion_page_with_retry(
        self,
    ) -> object:
        retry_index = 0

        while True:
            try:
                return (
                    self._ingestion_job.run()
                )

            except (
                GitHubAdvisoryConnectorError
            ) as error:
                if (
                    retry_index
                    >= len(
                        self
                        ._retry_delays_seconds
                    )
                ):
                    raise

                fallback_delay = (
                    self
                    ._retry_delays_seconds[
                        retry_index
                    ]
                )

                retry_delay = (
                    self._resolve_retry_delay(
                        error=error,
                        fallback_delay=(
                            fallback_delay
                        ),
                    )
                )

                if retry_delay is None:
                    raise

                retry_index += 1

                logger.warning(
                    "GitHub Advisory transient "
                    "ingestion failure; retrying "
                    "current page",
                    extra={
                        "retry_number": (
                            retry_index
                        ),
                        "retry_delay_seconds": (
                            retry_delay
                        ),
                        "error_type": (
                            type(
                                error
                            ).__name__
                        ),
                    },
                )

                self._sleeper(
                    retry_delay
                )

    @classmethod
    def _resolve_retry_delay(
        cls,
        *,
        error: GitHubAdvisoryConnectorError,
        fallback_delay: float,
    ) -> float | None:
        cause = error.__cause__

        if isinstance(
            cause,
            requests.Timeout,
        ):
            return fallback_delay

        if isinstance(
            cause,
            requests.HTTPError,
        ):
            response = cause.response

            if response is None:
                return fallback_delay

            status_code = (
                response.status_code
            )

            retryable = (
                status_code == 429
                or (
                    500
                    <= status_code
                    <= 599
                )
                or (
                    status_code == 403
                    and (
                        cls
                        ._response_indicates_rate_limit(
                            response
                        )
                    )
                )
            )

            if not retryable:
                return None

            retry_after = (
                cls._read_retry_after(
                    response
                )
            )

            if retry_after is None:
                return fallback_delay

            if (
                retry_after
                > cls.MAX_RETRY_DELAY_SECONDS
            ):
                return None

            return retry_after

        if isinstance(
            cause,
            requests.ConnectionError,
        ):
            return fallback_delay

        if isinstance(
            cause,
            requests.RequestException,
        ):
            return fallback_delay

        return None

    @staticmethod
    def _response_indicates_rate_limit(
        response: requests.Response,
    ) -> bool:
        remaining = (
            response.headers.get(
                "X-RateLimit-Remaining"
            )
        )

        if (
            remaining is not None
            and remaining.strip() == "0"
        ):
            return True

        text_value = (
            response.text or ""
        )

        return (
            "rate limit"
            in text_value.lower()
        )

    @staticmethod
    def _read_retry_after(
        response: requests.Response,
    ) -> float | None:
        raw_value = (
            response.headers.get(
                "Retry-After"
            )
        )

        if raw_value is None:
            return None

        normalized = (
            raw_value.strip()
        )

        if not normalized:
            return None

        try:
            value = float(
                normalized
            )

        except ValueError:
            return None

        if value < 0:
            return None

        return value

    @classmethod
    def _validate_max_pages(
        cls,
        value: int,
    ) -> None:
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
                "max_pages must be an integer"
            )

        if not (
            1
            <= value
            <= cls.MAX_ALLOWED_PAGES
        ):
            raise ValueError(
                "max_pages must be between "
                f"1 and {cls.MAX_ALLOWED_PAGES}"
            )

    @staticmethod
    def _validate_cycle_page_budget(
        value: int | None,
        *,
        max_pages: int,
    ) -> None:
        if value is None:
            return

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
                "cycle_page_budget "
                "must be an integer or None"
            )

        if value < 1:
            raise ValueError(
                "cycle_page_budget must be "
                "greater than zero"
            )

        if value > max_pages:
            raise ValueError(
                "cycle_page_budget must not "
                "exceed max_pages"
            )

    @classmethod
    def _validate_retry_delays(
        cls,
        values: tuple[
            float,
            ...,
        ],
    ) -> None:
        if not isinstance(
            values,
            tuple,
        ):
            raise TypeError(
                "retry_delays_seconds "
                "must be a tuple"
            )

        if len(values) > 10:
            raise ValueError(
                "too many GitHub retry delays"
            )

        for value in values:
            if (
                isinstance(
                    value,
                    bool,
                )
                or not isinstance(
                    value,
                    (int, float),
                )
            ):
                raise TypeError(
                    "GitHub retry delays "
                    "must be numeric"
                )

            if value < 0:
                raise ValueError(
                    "GitHub retry delays "
                    "must not be negative"
                )

            if (
                value
                > cls.MAX_RETRY_DELAY_SECONDS
            ):
                raise ValueError(
                    "GitHub retry delay "
                    "is too large"
                )


class EPSSRefreshStage:
    """
    Refresh EPSS uniquement pour les CVE déjà pertinentes
    pour les actifs de la plateforme.
    """

    DEFAULT_BATCH_SIZE = 500
    MAX_BATCH_SIZE = 1_000

    DEFAULT_MAX_BATCHES = 10_000

    def __init__(
        self,
        *,
        cve_reader: CanonicalCVEPageReader,
        synchronization_job: (
            EPSSSynchronizationRunner
        ),
        canonical_job: JobWithoutArguments,
        batch_size: int = DEFAULT_BATCH_SIZE,
        max_batches: int = (
            DEFAULT_MAX_BATCHES
        ),
    ) -> None:
        if cve_reader is None:
            raise ValueError(
                "cve_reader must not be None"
            )

        if synchronization_job is None:
            raise ValueError(
                "synchronization_job "
                "must not be None"
            )

        if canonical_job is None:
            raise ValueError(
                "canonical_job must not be None"
            )

        self._validate_batch_size(
            batch_size
        )

        self._validate_max_batches(
            max_batches
        )

        self._cve_reader = (
            cve_reader
        )

        self._synchronization_job = (
            synchronization_job
        )

        self._canonical_job = (
            canonical_job
        )

        self._batch_size = (
            batch_size
        )

        self._max_batches = (
            max_batches
        )

    def run(
        self,
    ) -> ThreatIntelligenceRefreshStageResult:
        cursor: str | None = None

        total_requested = 0
        total_fetched = 0
        total_submitted = 0

        batches_processed = 0
        source_exhausted = False

        for _ in range(
            self._max_batches
        ):
            cve_ids = (
                self._cve_reader
                .read_batch(
                    after_cve_id=cursor,
                    limit=self._batch_size,
                )
            )

            self._validate_cve_batch(
                cve_ids
            )

            if not cve_ids:
                source_exhausted = True
                break

            synchronization_result = (
                self._synchronization_job
                .run(
                    cve_ids
                )
            )

            total_requested += (
                CisaKevRefreshStage
                ._read_optional_non_negative_integer(
                    synchronization_result,
                    "requested_cves",
                    default=len(cve_ids),
                )
            )

            total_fetched += (
                CisaKevRefreshStage
                ._read_optional_non_negative_integer(
                    synchronization_result,
                    "fetched_scores",
                    default=0,
                )
            )

            total_submitted += (
                CisaKevRefreshStage
                ._read_non_negative_integer(
                    synchronization_result,
                    "submitted_scores",
                    stage_name=(
                        "EPSS synchronization"
                    ),
                )
            )

            batches_processed += 1

            next_cursor = (
                cve_ids[-1]
            )

            if next_cursor == cursor:
                raise RuntimeError(
                    "EPSS CVE pagination cursor "
                    "did not progress"
                )

            cursor = next_cursor

            if (
                len(cve_ids)
                < self._batch_size
            ):
                source_exhausted = True
                break

        if not source_exhausted:
            remaining = (
                self._cve_reader
                .read_batch(
                    after_cve_id=cursor,
                    limit=1,
                )
            )

            self._validate_cve_batch(
                remaining
            )

            if remaining:
                raise RuntimeError(
                    "EPSS refresh reached "
                    "max_batches before "
                    "all relevant CVEs "
                    "were processed"
                )

        canonical_result = (
            self._canonical_job.run()
        )

        canonical_records_read = (
            CisaKevRefreshStage
            ._validate_canonical_result(
                canonical_result,
                stage_name=(
                    "EPSS canonical "
                    "correlation"
                ),
            )
        )

        canonical_created = (
            CisaKevRefreshStage
            ._read_optional_non_negative_integer(
                canonical_result,
                "canonical_created",
                default=0,
            )
        )

        canonical_updated = (
            CisaKevRefreshStage
            ._read_optional_non_negative_integer(
                canonical_result,
                "canonical_updated",
                default=0,
            )
        )

        canonical_persisted = (
            CisaKevRefreshStage
            ._read_optional_non_negative_integer(
                canonical_result,
                "canonical_persisted",
                default=0,
            )
        )

        metrics = (
            ThreatIntelligenceStageMetrics(
                pages_processed=(
                    batches_processed
                ),
                records_received=(
                    total_fetched
                ),
                records_persisted=(
                    total_submitted
                ),
                normalization_claimed=(
                    total_requested
                ),
                normalized=(
                    total_submitted
                ),
                canonical_records_read=(
                    canonical_records_read
                ),
                canonical_created=(
                    canonical_created
                ),
                canonical_updated=(
                    canonical_updated
                ),
                canonical_persisted=(
                    canonical_persisted
                ),
                limit_reached=False,
            )
        )

        return (
            ThreatIntelligenceRefreshStageResult(
                changed=(
                    total_submitted > 0
                ),
                processed_count=(
                    total_submitted
                ),
                metrics=metrics,
            )
        )

    @staticmethod
    def _validate_cve_batch(
        values: tuple[
            str,
            ...,
        ],
    ) -> None:
        if not isinstance(
            values,
            tuple,
        ):
            raise TypeError(
                "CVE reader must return a tuple"
            )

        previous: str | None = None

        for value in values:
            if not isinstance(
                value,
                str,
            ):
                raise TypeError(
                    "CVE reader values must "
                    "be strings"
                )

            normalized = (
                value.strip().upper()
            )

            if not normalized:
                raise ValueError(
                    "CVE reader returned "
                    "an empty identifier"
                )

            if normalized != value:
                raise ValueError(
                    "CVE reader returned a "
                    "non-normalized identifier"
                )

            if (
                previous is not None
                and value <= previous
            ):
                raise RuntimeError(
                    "CVE reader batch must "
                    "be strictly ordered"
                )

            previous = value

    @classmethod
    def _validate_batch_size(
        cls,
        value: int,
    ) -> None:
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
                "batch_size must be an integer"
            )

        if not (
            1
            <= value
            <= cls.MAX_BATCH_SIZE
        ):
            raise ValueError(
                "batch_size must be between "
                f"1 and {cls.MAX_BATCH_SIZE}"
            )

    @staticmethod
    def _validate_max_batches(
        value: int,
    ) -> None:
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
                "max_batches must be an integer"
            )

        if value < 1:
            raise ValueError(
                "max_batches must be "
                "greater than zero"
            )