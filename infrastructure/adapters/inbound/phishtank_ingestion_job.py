from __future__ import annotations

from domain.collection_result import CollectionResult
from application.services.phishtank_threat_source import (
    PhishTankThreatSource,
)


class PhishTankIngestionJob:
    """
    Inbound adapter responsible for triggering a PhishTank
    intelligence ingestion.

    The job delegates all collection and normalization logic
    to PhishTankThreatSource.

    It must not contain:
    - HTTP communication;
    - snapshot download logic;
    - ETag synchronization logic;
    - raw data parsing;
    - Threat mapping logic.
    """

    def __init__(
        self,
        source: PhishTankThreatSource,
    ) -> None:
        """
        Initialize the ingestion job.

        Args:
            source:
                Application service responsible for collecting
                and normalizing PhishTank intelligence.
        """

        if source is None:
            raise ValueError(
                "PhishTank source must not be None."
            )

        self.source = source

    def run(self) -> CollectionResult:
        """
        Execute one PhishTank ingestion cycle.

        Returns:
            CollectionResult containing normalized Threat
            objects and collection metadata.
        """

        print(
            "\n[INFO] Starting PhishTank ingestion job..."
        )

        result = self.source.collect()

        self._print_summary(result)

        return result

    @staticmethod
    def _print_summary(
        result: CollectionResult,
    ) -> None:
        """
        Print a concise ingestion summary.
        """

        metadata = result.metadata

        print(
            "[INFO] PhishTank ingestion completed."
        )

        print(
            f"[INFO] Collected threats: "
            f"{len(result.threats)}"
        )

        print(
            f"[INFO] Raw records: "
            f"{metadata.get('raw_record_count', 0)}"
        )

        print(
            f"[INFO] Skipped records: "
            f"{metadata.get('skipped_record_count', 0)}"
        )

        downloaded = metadata.get("downloaded")
        used_local_snapshot = metadata.get(
            "used_local_snapshot"
        )

        if downloaded is True:
            print(
                "[INFO] Snapshot status: "
                "new snapshot downloaded."
            )
        elif used_local_snapshot is True:
            print(
                "[INFO] Snapshot status: "
                "local snapshot reused."
            )
        else:
            print(
                "[INFO] Snapshot status: unavailable."
            )

        etag = metadata.get("etag")

        if etag:
            print(
                f"[INFO] Snapshot ETag: {etag}"
            )

        last_modified = metadata.get(
            "last_modified"
        )

        if last_modified:
            print(
                f"[INFO] Last modified: "
                f"{last_modified}"
            )

