import logging #journalisation
from uuid import UUID

from application.services.ingestion_service import (
    IngestionResult,
    IngestionService,
)


logger = logging.getLogger(__name__)


class GitHubAdvisoryRawIngestionJob:
    def __init__(
        self,
        *,
        ingestion_service: IngestionService,
        source_id: UUID,
    ) -> None:
        if ingestion_service is None:
            raise ValueError(
                "ingestion_service must not be None"
            )

        if not isinstance(source_id, UUID):
            raise TypeError(
                "source_id must be a UUID"
            )

        self._ingestion_service = ingestion_service
        self._source_id = source_id

    def run(self) -> IngestionResult:
        logger.info(
            "GitHub advisory raw ingestion started",
            extra={
                "source_id": str(self._source_id),
            },
        )

        try:
            result = self._ingestion_service.ingest(
                source_id=self._source_id,
            )
        except Exception:
            logger.exception(
                "GitHub advisory raw ingestion failed",
                extra={
                    "source_id": str(self._source_id),
                },
            )
            raise

        self._log_summary(result)

        return result

    @staticmethod
    def _log_summary(
        result: IngestionResult,
    ) -> None:
        logger.info(
            "GitHub advisory raw ingestion completed",
            extra={
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

