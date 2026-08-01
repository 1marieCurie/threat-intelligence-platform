from __future__ import annotations

import logging
from dataclasses import dataclass
from uuid import UUID

from application.services.phishtank_normalization_service import (
    PhishTankNormalizationService,
)


logger = logging.getLogger(__name__)


@dataclass(
    frozen=True,
    slots=True,
)
class PhishTankNormalizationJobResult:
    """
    Résultat agrégé d'une exécution du job PhishTank.
    """

    batches: int
    claimed: int
    normalized: int
    already_normalized: int
    failed: int
    requeued: int
    stale_failed: int


class PhishTankNormalizationJob:
    """
    Orchestre la normalisation PhishTank par lots.

    Le service conserve la responsabilité :

    - des transactions ;
    - de la réservation des payloads ;
    - de la récupération des leases ;
    - de la normalisation ;
    - de la persistance ;
    - des transitions processed/failed.

    Le job gère uniquement :

    - l'enchaînement borné des lots ;
    - l'agrégation des résultats ;
    - les logs non sensibles.
    """

    DEFAULT_MAX_BATCHES = 10_000

    _MAX_BATCHES_ERROR = (
        "PhishTank normalization reached "
        "max_batches before completion"
    )

    _UNEXPECTED_ERROR_SUMMARY = (
        "unexpected normalization job failure"
    )

    def __init__(
        self,
        *,
        normalization_service: (
            PhishTankNormalizationService
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

        if not isinstance(
            source_id,
            UUID,
        ):
            raise TypeError(
                "source_id must be a UUID"
            )

        if not isinstance(
            source_code,
            str,
        ):
            raise TypeError(
                "source_code must be a string"
            )

        normalized_source_code = (
            source_code
            .strip()
            .upper()
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
    ) -> PhishTankNormalizationJobResult:
        logger.info(
            "PhishTank normalization started",
            extra={
                "source_id": str(
                    self._source_id
                ),
                "source_code": (
                    self._source_code
                ),
                "batch_size": (
                    self._batch_size
                ),
                "max_batches": (
                    self._max_batches
                ),
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
                    self
                    ._normalization_service
                    .process_pending(
                        source_id=(
                            self._source_id
                        ),
                        limit=(
                            self._batch_size
                        ),
                    )
                )

                claimed += (
                    batch_result.claimed
                )

                normalized += (
                    batch_result.normalized
                )

                already_normalized += (
                    batch_result
                    .already_normalized
                )

                failed += (
                    batch_result.failed
                )

                requeued += (
                    batch_result.requeued
                )

                stale_failed += (
                    batch_result.stale_failed
                )

                if (
                    batch_result.claimed
                    == 0
                ):
                    result = (
                        PhishTankNormalizationJobResult(
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
                self._MAX_BATCHES_ERROR
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
        result: PhishTankNormalizationJobResult,
    ) -> None:
        logger.info(
            "PhishTank normalization completed",
            extra={
                "source_id": str(
                    self._source_id
                ),
                "source_code": (
                    self._source_code
                ),
                "batches": result.batches,
                "claimed": result.claimed,
                "normalized": (
                    result.normalized
                ),
                "already_normalized": (
                    result
                    .already_normalized
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
        N'écrit ni traceback ni message technique externe.

        Une exception SQL peut contenir les paramètres de la
        requête, y compris une URL IOC complète.
        """

        error_type = (
            type(error).__name__
        )

        if (
            isinstance(
                error,
                RuntimeError,
            )
            and str(error)
            == self._MAX_BATCHES_ERROR
        ):
            error_summary = (
                f"{error_type}: "
                f"{self._MAX_BATCHES_ERROR}"
            )
        else:
            error_summary = (
                f"{error_type}: "
                f"{self._UNEXPECTED_ERROR_SUMMARY}"
            )

        logger.error(
            "PhishTank normalization failed",
            extra={
                "source_id": str(
                    self._source_id
                ),
                "source_code": (
                    self._source_code
                ),
                "batches": batches,
                "claimed": claimed,
                "normalized": normalized,
                "failed": failed,
                "error_summary": (
                    error_summary
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
            or not isinstance(
                value,
                int,
            )
        ):
            raise TypeError(
                f"{field_name} must be an integer"
            )

        if value < 1:
            raise ValueError(
                f"{field_name} must be "
                "greater than zero"
            )