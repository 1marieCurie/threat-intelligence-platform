from abc import ABC, abstractmethod
from typing import Any, List

from domain.threat import Threat
from domain.collection_result import CollectionResult


class ThreatSource(ABC):
    """
    Inbound Port (Hexagonal Architecture)

    This interface defines the contract that every Threat Source must respect.

    A Threat Source is responsible for collecting vulnerabilities from any external provider
    (NVD, MITRE, CISA, GitHub, etc.) and returning a normalized collection result.
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