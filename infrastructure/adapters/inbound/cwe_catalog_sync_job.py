from __future__ import annotations

import logging

from application.security.sensitive_data_redactor import (
    redact_sensitive_data,
)
from application.services.cwe_catalog_sync_service import (
    CWECatalogSyncResult,
    CWECatalogSyncService,
)


logger = logging.getLogger(__name__)


class CWECatalogSyncJob:
    """
    Point d'entrée applicatif du synchroniseur CWE.

    Le service conserve la responsabilité :
    - de l'extraction des références ;
    - des appels MITRE ;
    - du mapping ;
    - des transactions PostgreSQL.

    Le job gère uniquement l'orchestration et les logs.
    """

    def __init__(
        self,
        *,
        sync_service: CWECatalogSyncService,
    ) -> None:
        if sync_service is None:
            raise ValueError(
                "sync_service must not be None"
            )

        self._sync_service = sync_service

    def run(
        self,
    ) -> CWECatalogSyncResult:
        """
        Lance une synchronisation bornée du catalogue CWE.
        """

        logger.info(
            "CWE catalog synchronization started"
        )

        try:
            result = (
                self._sync_service
                .synchronize_referenced()
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
        result: CWECatalogSyncResult,
    ) -> None:
        """
        Journalise uniquement des métadonnées et compteurs.

        La liste des CWE manquants n'est pas écrite dans les logs
        afin d'éviter des journaux volumineux.
        """

        logger.info(
            "CWE catalog synchronization completed",
            extra={
                "catalog_version": (
                    result.catalog_version
                ),
                "catalog_date": (
                    result.catalog_date
                ),
                "requested_ids": (
                    result.requested_ids
                ),
                "fetched_weaknesses": (
                    result.fetched_weaknesses
                ),
                "persisted_weaknesses": (
                    result.persisted_weaknesses
                ),
                "up_to_date_weaknesses": (
                    result.up_to_date_weaknesses
                ),
                "batches": result.batches,
                "missing_ids_count": len(
                    result.missing_ids
                ),
            },
        )
    @staticmethod
    def _log_failure(
        error: Exception,
    ) -> None:
        """
        Journalise une erreur assainie sans traceback.

        Les erreurs HTTP ou PostgreSQL peuvent contenir une URL,
        un mot de passe ou une chaîne de connexion.
        """

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

        logger.error(
            "CWE catalog synchronization failed",
            extra={
                "error_type": error_type,
                "error_summary": (
                    sanitized_summary
                ),
            },
        )