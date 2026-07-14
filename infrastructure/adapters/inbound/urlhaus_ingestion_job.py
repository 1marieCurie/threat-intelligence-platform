from __future__ import annotations

from typing import Protocol

from domain.collection_result import CollectionResult


class CollectingThreatSource(Protocol):
    def collect(self) -> CollectionResult:
        ...


class URLhausIngestionJob:
    """
    Inbound adapter triggering the URLhaus ingestion workflow.
    """

    def __init__(
        self,
        source: CollectingThreatSource,
    ) -> None:
        self._source = source

    @property
    def source(self) -> CollectingThreatSource:
        return self._source

    def run(self) -> CollectionResult:
        result = self._source.collect()

        if not isinstance(result, CollectionResult):
            raise TypeError(
                "URLhaus source collect() must return "
                "a CollectionResult."
            )

        return result