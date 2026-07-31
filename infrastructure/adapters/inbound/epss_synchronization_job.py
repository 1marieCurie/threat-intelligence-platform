from __future__ import annotations

import logging
import re
from collections.abc import Iterable
from datetime import date

from application.security.sensitive_data_redactor import (
    redact_sensitive_data,
)
from application.services.epss_synchronization_service import (
    EPSSSynchronizationResult,
    EPSSSynchronizationService,
)


logger = logging.getLogger(__name__)

_CVE_IDENTIFIER_PATTERN = re.compile(
    r"\bCVE-[A-Z0-9._-]+\b",
    flags=re.IGNORECASE,
)

_CVE_REDACTED_VALUE = "[CVE_REDACTED]"


class EPSSSynchronizationJob:
    """
    Point d'entrée du pipeline de synchronisation EPSS.

    Le service applicatif conserve la responsabilité :

    - de la validation et de la normalisation des CVE ;
    - de l'appel au provider FIRST ;
    - de l'ouverture de la transaction PostgreSQL ;
    - de l'upsert et du commit.

    Le job est uniquement responsable :

    - du déclenchement du service ;
    - de la journalisation non sensible ;
    - de la propagation des erreurs au CLI ou à l'ordonnanceur.
    """

    def __init__(
        self,
        *,
        synchronization_service: (
            EPSSSynchronizationService
        ),
    ) -> None:
        if synchronization_service is None:
            raise ValueError(
                "synchronization_service "
                "must not be None"
            )

        self._synchronization_service = (
            synchronization_service
        )

    def run(
        self,
        cve_ids: Iterable[str],
        *,
        score_date: date | None = None,
    ) -> EPSSSynchronizationResult:
        """
        Lance une synchronisation EPSS bornée.

        Les collections et identifiants sont validés par
        EPSSSynchronizationService afin de conserver une seule
        source de vérité pour les règles applicatives.
        """
        logger.info(
            "EPSS synchronization started",
            extra={
                "historical_sync": (
                    score_date is not None
                ),
                "requested_score_date": (
                    score_date.isoformat()
                    if score_date is not None
                    else None
                ),
            },
        )

        try:
            result = (
                self._synchronization_service
                .synchronize(
                    cve_ids,
                    score_date=score_date,
                )
            )

            self._log_completion(
                result
            )

            return result

        except Exception as error:
            self._log_failure(
                error
            )
            raise

    @staticmethod
    def _log_completion(
        result: EPSSSynchronizationResult,
    ) -> None:
        """
        Journalise uniquement des compteurs.

        Les CVE demandés ou manquants ne sont jamais ajoutés
        aux logs.
        """
        logger.info(
            "EPSS synchronization completed",
            extra={
                "requested_cves": (
                    result.requested_cves
                ),
                "fetched_scores": (
                    result.fetched_scores
                ),
                "submitted_scores": (
                    result.submitted_scores
                ),
                "missing_cves_count": len(
                    result.missing_cves
                ),
                "historical_sync": (
                    result.requested_score_date
                    is not None
                ),
                "requested_score_date": (
                    result
                    .requested_score_date
                    .isoformat()
                    if (
                        result.requested_score_date
                        is not None
                    )
                    else None
                ),
            },
        )

    @staticmethod
    def _log_failure(
        error: Exception,
    ) -> None:
        """
        Journalise une erreur assainie sans traceback.

        Les secrets techniques et les identifiants CVE
        sont supprimés avant l'écriture.
        """
        error_type = type(
            error
        ).__name__

        sanitized_summary = (
            EPSSSynchronizationJob
            ._sanitize_error_summary(
                error
            )
        )

        logger.error(
            "EPSS synchronization failed",
            extra={
                "error_type": error_type,
                "error_summary": (
                    sanitized_summary
                ),
            },
        )

    @staticmethod
    def _sanitize_error_summary(
        error: Exception,
    ) -> str:
        error_type = type(
            error
        ).__name__

        error_message = str(
            error
        ).strip()

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

        return _CVE_IDENTIFIER_PATTERN.sub(
            _CVE_REDACTED_VALUE,
            sanitized_summary,
        )