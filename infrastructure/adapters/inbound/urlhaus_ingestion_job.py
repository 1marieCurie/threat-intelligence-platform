from __future__ import annotations

from typing import Protocol, runtime_checkable

from domain.collection_result import CollectionResult


@runtime_checkable
class URLhausCollectingSource(Protocol):
    """
    Minimal contract required by URLhausIngestionJob.

    The ingestion job depends on a capability, not on the
    concrete URLhausThreatSource implementation.
    """

    def collect(self) -> CollectionResult:
        ...


class URLhausIngestionJob:
    """
    Inbound adapter responsible for triggering URLhaus ingestion.

    The job delegates collection and normalization to a compatible
    source and validates the returned application result.
    """

    def __init__(
        self,
        source: URLhausCollectingSource,
    ) -> None:
        if source is None:
            raise ValueError(
                "source is required."
            )

        if not isinstance(
            source,
            URLhausCollectingSource,
        ):
            raise TypeError(
                "source must provide a collect() method."
            )

        self._source = source

    @property
    def source(
        self,
    ) -> URLhausCollectingSource:
        return self._source

    def run(self) -> CollectionResult:
        result = self._source.collect()

        if not isinstance(
            result,
            CollectionResult,
        ):
            raise TypeError(
                "URLhaus source collect() must return "
                "a CollectionResult."
            )

        return result