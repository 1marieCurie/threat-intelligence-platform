from __future__ import annotations

import logging
from uuid import UUID

from application.services.ingestion_service import (
    IngestionResult,
    IngestionService,
)


logger = logging.getLogger(__name__)


class RawIngestionJob:
    """
    Point d'entrée générique pour une ingestion brute.

    Le job orchestre l'exécution et la journalisation.
    La récupération et la persistance restent déléguées
    à IngestionService et à ses ports.
    """

    def __init__(
        self,
        *,
        ingestion_service: IngestionService,
        source_id: UUID,
        source_code: str,
    ) -> None:
        if ingestion_service is None:
            raise ValueError(
                "ingestion_service must not be None"
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

        self._ingestion_service = ingestion_service
        self._source_id = source_id
        self._source_code = normalized_source_code

    def run(self) -> IngestionResult:
        logger.info(
            "Raw ingestion started",
            extra={
                "source_id": str(self._source_id),
                "source_code": self._source_code,
            },
        )

        try:
            result = self._ingestion_service.ingest(
                source_id=self._source_id,
            )
        except Exception:
            logger.exception(
                "Raw ingestion failed",
                extra={
                    "source_id": str(self._source_id),
                    "source_code": self._source_code,
                },
            )
            raise

        logger.info(
            "Raw ingestion completed",
            extra={
                "source_id": str(self._source_id),
                "source_code": self._source_code,
                "run_id": str(result.run_id),
                "records_received": (
                    result.records_received
                ),
                "records_persisted": (
                    result.records_persisted
                ),
                "records_skipped": (
                    result.records_skipped
                ),
                "status": result.status,
                "pagination_complete": (
                    result.pagination_complete
                ),
            },
        )

        return result