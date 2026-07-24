from uuid import UUID

from application.services.ingestion_service import (
    IngestionResult,
    IngestionService,
)


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
        result = self._ingestion_service.ingest(
            source_id=self._source_id,
        )

        self._print_summary(result)

        return result

    @staticmethod
    def _print_summary(
        result: IngestionResult,
    ) -> None:
        print(
            "GitHub advisory raw ingestion completed: "
            f"received={result.records_received}, "
            f"persisted={result.records_persisted}, "
            f"skipped={result.records_skipped}, "
            f"status={result.status}"
        )