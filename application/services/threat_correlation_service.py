from dataclasses import dataclass, field
from typing import Any, Dict, List

from application.ports.inbound.threat_source import ThreatSource
from domain.collection_result import CollectionResult
from domain.threat import Threat


@dataclass
class CorrelatedThreat:
    """
    Represents a group of Threat objects referring to the same vulnerability ID.

    This class does not merge source-specific data.
    It only correlates Threat objects by their identifier.
    """

    id: str
    sources: List[str] = field(default_factory=list)
    threats: List[Threat] = field(default_factory=list)
    threats_by_source: Dict[str, List[Threat]] = field(default_factory=dict)

    def add(
        self,
        source: str,
        threat: Threat
    ):
        """
        Adds a Threat coming from a specific source.
        """

        if source not in self.sources:
            self.sources.append(source)

        self.threats.append(threat)

        if source not in self.threats_by_source:
            self.threats_by_source[source] = []

        self.threats_by_source[source].append(threat)

    @property
    def source_count(self) -> int:
        """
        Returns the number of distinct sources that reported this threat.
        """

        return len(self.sources)

    @property
    def is_multi_source(self) -> bool:
        """
        Indicates whether the threat was reported by more than one source.
        """

        return self.source_count > 1


@dataclass
class ThreatCorrelationResult:
    """
    Represents the result of correlating multiple threat collections.

    The result keeps all original Threat objects grouped by ID,
    without performing data fusion.
    """

    groups: Dict[str, CorrelatedThreat] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def unique_ids(self) -> List[str]:
        """
        Returns all unique threat identifiers.
        """

        return list(self.groups.keys())

    def multi_source_groups(self) -> List[CorrelatedThreat]:
        """
        Returns only threats reported by more than one source.
        """

        return [
            group
            for group in self.groups.values()
            if group.is_multi_source
        ]

    def all_groups(self) -> List[CorrelatedThreat]:
        """
        Returns all correlated threat groups.
        """

        return list(self.groups.values())


class ThreatCorrelationService:
    """
    Application Service

    Performs minimal correlation between multiple threat intelligence sources.

    This service:
    - receives CollectionResult objects from different sources;
    - groups Threat objects by their ID;
    - preserves all original source-specific Threat objects;
    - does not perform field-level fusion.

    This is intentionally a correlation layer, not a fusion layer.
    """

    def collect_and_correlate(
        self,
        sources: List[ThreatSource]
    ) -> ThreatCorrelationResult:
        """
        Collects threats from multiple ThreatSource implementations
        and correlates the resulting CollectionResult objects.
        """

        collection_results = []

        for source in sources:

            result = source.collect()

            collection_results.append(result)

        return self.correlate_results(
            collection_results
        )

    def correlate_results(
        self,
        collection_results: List[CollectionResult]
    ) -> ThreatCorrelationResult:
        """
        Correlates several CollectionResult objects by Threat ID.
        """

        groups: Dict[str, CorrelatedThreat] = {}

        source_summaries = []
        total_input_threats = 0

        for result in collection_results:

            source_name = (
                result.metadata.get("source")
                or "UNKNOWN"
            )

            source_threat_count = len(result.threats)

            total_input_threats += source_threat_count

            source_summaries.append(
                {
                    "source": source_name,
                    "threats": source_threat_count
                }
            )

            for threat in result.threats:

                if not threat.id:
                    continue

                if threat.id not in groups:
                    groups[threat.id] = CorrelatedThreat(
                        id=threat.id
                    )

                groups[threat.id].add(
                    source=source_name,
                    threat=threat
                )

        multi_source_count = len(
            [
                group
                for group in groups.values()
                if group.is_multi_source
            ]
        )

        metadata = {
            "total_sources": len(collection_results),
            "source_summaries": source_summaries,
            "total_input_threats": total_input_threats,
            "unique_threats": len(groups),
            "multi_source_threats": multi_source_count
        }

        return ThreatCorrelationResult(
            groups=groups,
            metadata=metadata
        )