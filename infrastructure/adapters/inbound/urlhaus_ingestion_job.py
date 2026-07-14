from __future__ import annotations

from typing import Optional

from application.services.urlhaus_threat_source import (
    URLhausThreatSource,
)
from domain.collection_result import CollectionResult

class URLhausIngestionJob:
    """
    Inbound adapter responsible for triggering URLhaus ingestion.

    The job delegates collection and normalization to
    URLhausThreatSource and returns the resulting CollectionResult.

    It does not contain HTTP logic or URLhaus parsing logic.
    """

    def __init__(
        self,
        source: URLhausThreatSource,
    ) -> None:
        """
        Initialize the ingestion job.

        Args:
            source:
                URLhaus application service used to collect and
                normalize URLhaus intelligence.

        Raises:
            TypeError:
                If source is not a URLhausThreatSource instance.
        """
        if not isinstance(source, URLhausThreatSource):
            raise TypeError(
                "source must be an instance of "
                "URLhausThreatSource."
            )

        self._source = source

    @property
    def source(self) -> URLhausThreatSource:
        """
        Return the configured URLhaus source service.
        """
        return self._source

    def run(self) -> CollectionResult:
        """
        Execute the URLhaus ingestion workflow.

        Returns:
            CollectionResult containing normalized Threat objects
            and collection metadata.
        """
        result = self._source.collect()

        if not isinstance(result, CollectionResult):
            raise TypeError(
                "URLhausThreatSource.collect() must return "
                "a CollectionResult."
            )

        return result