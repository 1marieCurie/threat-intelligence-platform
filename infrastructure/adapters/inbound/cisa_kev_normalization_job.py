from __future__ import annotations

import logging
from dataclasses import dataclass
from uuid import UUID

from application.security.sensitive_data_redactor import (
    redact_sensitive_data,
)
from application.services.cisa_kev_normalization_service import (
    CisaKevNormalizationService,
)


logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class CisaKevNormalizationJobResult:
    """
    Résultat agrégé d'une exécution complète du job.
    """

    batches: int
    claimed: int
    normalized: int
    already_normalized: int
    failed: int
    requeued: int
    stale_failed: int


class CisaKevNormalizationJob:
    """
    Orchestre la normalisation des payloads CISA KEV par lots.

    Le service de normalisation conserve la responsabilité :

    - des transactions ;
    - de la récupération des leases expirées ;
    - de la réservation atomique des payloads ;
    - de la normalisation ;
    - de la persistance ;
    - des transitions processed/failed.

    Le job est uniquement responsable :

    - de l'enchaînement des lots ;
    - de l'agrégation des résultats ;
    - de la journalisation non sensible ;
    - de la protection contre les boucles non bornées.
    """

    DEFAULT_MAX_BATCHES = 10_000

    def __init__(
        self,
        *,
        normalization_service: CisaKevNormalizationService,
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

    def run(self) -> CisaKevNormalizationJobResult:
        """
        Traite les payloads jusqu'à obtenir un lot vide.

        Un lot vide signifie qu'aucun payload pending n'a pu être
        réservé pour cette source.

        Raises:
            RuntimeError:
                Si max_batches est atteint avant la fin du
                traitement.

            Exception:
                Propage les erreurs techniques levées par le service.
                Les informations journalisées sont assainies avant
                leur écriture dans les logs.
        """

        logger.info(
            "CISA KEV normalization started",
            extra={
                "source_id": str(self._source_id),
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
            for _ in range(self._max_batches):
                batch_result = (
                    self._normalization_service
                    .process_pending(
                        source_id=self._source_id,
                        limit=self._batch_size,
                    )
                )

                claimed += batch_result.claimed
                normalized += batch_result.normalized
                already_normalized += (
                    batch_result.already_normalized
                )
                failed += batch_result.failed
                requeued += batch_result.requeued
                stale_failed += (
                    batch_result.stale_failed
                )

                if batch_result.claimed == 0:
                    result = (
                        CisaKevNormalizationJobResult(
                            batches=batches,
                            claimed=claimed,
                            normalized=normalized,
                            already_normalized=(
                                already_normalized
                            ),
                            failed=failed,
                            requeued=requeued,
                            stale_failed=stale_failed,
                        )
                    )

                    self._log_completion(result)

                    return result

                batches += 1

            raise RuntimeError(
                "CISA KEV normalization reached "
                "max_batches before completion"
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
        result: CisaKevNormalizationJobResult,
    ) -> None:
        """
        Journalise uniquement des identifiants et compteurs.

        Aucun payload brut n'est ajouté aux logs.
        """

        logger.info(
            "CISA KEV normalization completed",
            extra={
                "source_id": str(self._source_id),
                "source_code": self._source_code,
                "batches": result.batches,
                "claimed": result.claimed,
                "normalized": result.normalized,
                "already_normalized": (
                    result.already_normalized
                ),
                "failed": result.failed,
                "requeued": result.requeued,
                "stale_failed": result.stale_failed,
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
        Journalise une erreur technique assainie.

        logger.exception() n'est volontairement pas utilisé ici :
        une traceback peut contenir des arguments, URLs ou secrets
        transmis par une dépendance externe.
        """

        error_type = type(error).__name__
        error_message = str(error).strip()

        raw_summary = (
            f"{error_type}: {error_message}"
            if error_message
            else error_type
        )

        sanitized_summary = redact_sensitive_data(
            raw_summary,
            max_length=500,
        )

        logger.error(
            "CISA KEV normalization failed",
            extra={
                "source_id": str(self._source_id),
                "source_code": self._source_code,
                "batches": batches,
                "claimed": claimed,
                "normalized": normalized,
                "failed": failed,
                "error_summary": sanitized_summary,
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
                f"{field_name} must be greater than zero"
            )