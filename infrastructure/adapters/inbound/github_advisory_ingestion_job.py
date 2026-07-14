from __future__ import annotations

from application.services.github_advisory_threat_source import (
    GitHubAdvisoryThreatSource,
)
from domain.collection_result import CollectionResult


class GitHubAdvisoryIngestionJob:
    """
    Inbound adapter responsible for triggering one GitHub
    Advisory ingestion cycle.

    The job delegates collection and normalization to
    GitHubAdvisoryThreatSource.

    It must not contain:
    - HTTP communication;
    - GitHub API pagination logic;
    - advisory filtering logic;
    - raw advisory parsing;
    - Threat mapping logic.
    """

    def __init__(
        self,
        source: GitHubAdvisoryThreatSource,
    ) -> None:
        """
        Initialize the GitHub Advisory ingestion job.

        Args:
            source:
                Application service responsible for collecting
                and normalizing GitHub Security Advisories.
        """

        if source is None:
            raise ValueError(
                "GitHub Advisory source must not be None."
            )

        self.source = source

    def run(self) -> CollectionResult:
        """
        Execute one GitHub Advisory ingestion cycle.

        Returns:
            The CollectionResult returned by the application
            service without modifying it.
        """

        print(
            "\n[INFO] Starting GitHub Advisory ingestion job..."
        )

        result = self.source.collect()

        self._print_summary(result)

        return result

    @staticmethod
    def _print_summary(
        result: CollectionResult,
    ) -> None:
        """
        Print a concise GitHub Advisory ingestion summary.
        """

        metadata = result.metadata

        print(
            "[INFO] GitHub Advisory ingestion completed."
        )

        print(
            f"[INFO] Collected threats: "
            f"{len(result.threats)}"
        )

        print(
            f"[INFO] Raw advisories: "
            f"{metadata.get('collected_count', 0)}"
        )

        print(
            f"[INFO] Parsed advisories: "
            f"{metadata.get('parsed_count', len(result.threats))}"
        )

        print(
            f"[INFO] Skipped advisories: "
            f"{metadata.get('skipped_count', 0)}"
        )

        advisory_type = metadata.get(
            "advisory_type"
        )

        if advisory_type:
            print(
                f"[INFO] Advisory type: "
                f"{advisory_type}"
            )

        ecosystem = metadata.get(
            "ecosystem"
        )

        if ecosystem:
            print(
                f"[INFO] Ecosystem filter: "
                f"{ecosystem}"
            )
        else:
            print(
                "[INFO] Ecosystem filter: all ecosystems."
            )

        severity = metadata.get(
            "severity"
        )

        if severity:
            print(
                f"[INFO] Severity filter: "
                f"{severity}"
            )
        else:
            print(
                "[INFO] Severity filter: all severities."
            )

        modified = metadata.get(
            "modified"
        )

        if modified:
            print(
                f"[INFO] Modified range: "
                f"{modified}"
            )

        per_page = metadata.get(
            "per_page"
        )

        if per_page is not None:
            print(
                f"[INFO] Results per page: "
                f"{per_page}"
            )

        max_pages = metadata.get(
            "max_pages"
        )

        if max_pages is None:
            print(
                "[INFO] Maximum pages: unlimited."
            )
        else:
            print(
                f"[INFO] Maximum pages: "
                f"{max_pages}"
            )

        api_version = metadata.get(
            "api_version"
        )

        if api_version:
            print(
                f"[INFO] GitHub API version: "
                f"{api_version}"
            )

        collected_at = metadata.get(
            "collected_at"
        )

        if collected_at:
            print(
                f"[INFO] Collected at: "
                f"{collected_at}"
            )