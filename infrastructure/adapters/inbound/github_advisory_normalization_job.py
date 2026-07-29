from __future__ import annotations

import logging
from dataclasses import dataclass
from uuid import UUID

from application.security.sensitive_data_redactor import (
    redact_sensitive_data,
)
from application.services.github_advisory_normalization_service import (
    GitHubAdvisoryNormalizationService,
)


logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class GitHubAdvisoryNormalizationJobResult:
    """
    Résultat agrégé d'une exécution complète du job GHAD.
    """

    batches: int
    claimed: int
    normalized: int
    already_normalized: int
    failed: int
    requeued: int
    stale_failed: int


class GitHubAdvisoryNormalizationJob:
    """
    Orchestre la normalisation GHAD par lots bornés.

    Le service conserve la responsabilité des transactions,
    des claims atomiques, des leases et de la persistance.
    """

    DEFAULT_MAX_BATCHES = 10_000

    def __init__(
        self,
        *,
        normalization_service: (
            GitHubAdvisoryNormalizationService
        ),
        source_id: UUID,
        source_code: str,
        batch_size: int = 100,
        max_batches: int = DEFAULT_MAX_BATCHES,
    ) -> None:
        if normalization_service is None:
            raise ValueError(
                "normalization_service must not be None"
            )

        if not isinstance(source_id, UUID):
            raise TypeError(
                "source_id must be a UUID"
            )

        if not isinstance(source_code, str):
            raise TypeError(
                "source_code must be a string"
            )

        normalized_source_code = (
            source_code.strip().upper()
        )

        if not normalized_source_code:
            raise ValueError(
                "source_code must not be empty"
            )

        self._validate_positive_integer(
            value=batch_size,
            field_name="batch_size",
        )

        self._validate_positive_integer(
            value=max_batches,
            field_name="max_batches",
        )

        self._normalization_service = (
            normalization_service
        )
        self._source_id = source_id
        self._source_code = normalized_source_code
        self._batch_size = batch_size
        self._max_batches = max_batches

    def run(
        self,
    ) -> GitHubAdvisoryNormalizationJobResult:
        """
        Traite les payloads jusqu'à obtenir un lot vide.

        Une limite de lots protège la plateforme contre une
        boucle infinie ou une alimentation continue anormale.
        """

        logger.info(
            "GitHub Advisory normalization started",
            extra={
                "source_id": str(
                    self._source_id
                ),
                "source_code": self._source_code,
                "batch_size": self._batch_size,
                "max_batches": self._max_batches,
            },
        )

        batches = 0
        claimed = 0
        normalized = 0
        already_normalized = 0
        failed = 0
        requeued = 0
        stale_failed = 0

        try:
            for _ in range(
                self._max_batches
            ):
                batch_result = (
                    self._normalization_service
                    .process_pending(
                        source_id=self._source_id,
                        limit=self._batch_size,
                    )
                )

                claimed += batch_result.claimed
                normalized += (
                    batch_result.normalized
                )

                already_normalized += (
                    batch_result
                    .already_normalized
                )

                failed += batch_result.failed
                requeued += batch_result.requeued
                stale_failed += (
                    batch_result.stale_failed
                )

                if batch_result.claimed == 0:
                    result = (
                        GitHubAdvisoryNormalizationJobResult(
                            batches=batches,
                            claimed=claimed,
                            normalized=normalized,
                            already_normalized=(
                                already_normalized
                            ),
                            failed=failed,
                            requeued=requeued,
                            stale_failed=(
                                stale_failed
                            ),
                        )
                    )

                    self._log_completion(
                        result
                    )

                    return result

                batches += 1

            raise RuntimeError(
                "GitHub Advisory normalization "
                "reached max_batches before "
                "completion"
            )

        except Exception as error:
            self._log_failure(
                error=error,
                batches=batches,
                claimed=claimed,
                normalized=normalized,
                failed=failed,
            )

            raise

    def _log_completion(
        self,
        result: (
            GitHubAdvisoryNormalizationJobResult
        ),
    ) -> None:
        """
        Journalise uniquement des identifiants et compteurs.
        """

        logger.info(
            "GitHub Advisory normalization completed",
            extra={
                "source_id": str(
                    self._source_id
                ),
                "source_code": self._source_code,
                "batches": result.batches,
                "claimed": result.claimed,
                "normalized": result.normalized,
                "already_normalized": (
                    result.already_normalized
                ),
                "failed": result.failed,
                "requeued": result.requeued,
                "stale_failed": (
                    result.stale_failed
                ),
            },
        )

    def _log_failure(
        self,
        *,
        error: Exception,
        batches: int,
        claimed: int,
        normalized: int,
        failed: int,
    ) -> None:
        """
        Journalise une erreur assainie sans traceback.

        Une traceback externe pourrait contenir un token,
        une URL signée ou des données issues du payload.
        """

        error_type = type(error).__name__
        error_message = str(error).strip()

        raw_summary = (
            f"{error_type}: {error_message}"
            if error_message
            else error_type
        )

        sanitized_summary = (
            redact_sensitive_data(
                raw_summary,
                max_length=500,
            )
        )

        logger.error(
            "GitHub Advisory normalization failed",
            extra={
                "source_id": str(
                    self._source_id
                ),
                "source_code": self._source_code,
                "batches": batches,
                "claimed": claimed,
                "normalized": normalized,
                "failed": failed,
                "error_summary": (
                    sanitized_summary
                ),
            },
        )

    @staticmethod
    def _validate_positive_integer(
        *,
        value: int,
        field_name: str,
    ) -> None:
        if (
            isinstance(value, bool)
            or not isinstance(value, int)
        ):
            raise TypeError(
                f"{field_name} must be an integer"
            )

        if value < 1:
            raise ValueError(
                f"{field_name} must be "
                "greater than zero"
            )