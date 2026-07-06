from abc import ABC, abstractmethod
from typing import List, Dict, Any

from domain.threat import Threat


class ThreatSource(ABC):
    """
    Inbound Port (Hexagonal Architecture)

    This interface defines the contract that every Threat Source must respect.
    A Threat Source is responsible for collecting vulnerabilities from any external provider
    (NVD, MITRE, CISA, GitHub, etc.) and returning a normalized list of Threat objects.
    """

    @abstractmethod
    def name(self) -> str:
        """
        Returns the name of the source (e.g., "NVD", "MITRE").
        Useful for logging, tracing, and multi-source aggregation.
        """
        pass

    @abstractmethod
    def collect(self) -> List[Threat]:
        """
        Main entry point of the source.

        This method is responsible for:
        - triggering data retrieval
        - transforming raw data into Threat objects
        - returning a normalized list of threats
        """
        pass

    @abstractmethod
    def fetch_raw(self) -> Any:
        """
        Optional but useful separation:
        Fetch raw data from external source (API, file, etc.)

        This keeps I/O separated from transformation logic.
        """
        pass

    @abstractmethod
    def parse(self, raw_data: Any) -> List[Threat]:
        """
        Converts raw data into domain objects (Threat).

        This ensures:
        - domain consistency
        - decoupling from external formats (JSON, XML, etc.)
        """
        pass