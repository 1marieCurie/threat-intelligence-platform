from abc import ABC, abstractmethod
from typing import Any, List

from domain.threat import Threat
from domain.collection_result import CollectionResult


class ThreatSource(ABC):
    """
    Inbound port for cybersecurity intelligence sources.

    Every external source must implement this contract.

    A source is responsible for retrieving cybersecurity
    intelligence from an external provider and converting it
    into normalized Threat objects.
    """

    @abstractmethod
    def name(self) -> str:
        """
        Returns the name of the source (e.g., "NVD", "CISA").
        Useful for logging, tracing, and multi-source aggregation.
        """
        pass

    @abstractmethod
    def collect(self) -> CollectionResult:
        """
        Main entry point of the source.

        This method is responsible for:
        - triggering data retrieval
        - transforming raw data into Threat objects
        - collecting ingestion metadata
        - returning a normalized collection result
        """
        pass

    @abstractmethod
    def fetch_raw(self) -> Any:
        """
        Fetch raw data from the external source (API, file, etc.).

        Keeps external communication separated from transformation logic.
        """
        pass

    @abstractmethod
    def parse(self, raw_data: Any) -> List[Threat]:
        """
        Converts raw data into domain Threat objects.

        Ensures:
        - domain consistency
        - decoupling from external formats (JSON, XML, etc.)
        """
        pass