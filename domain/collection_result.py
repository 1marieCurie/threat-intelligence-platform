from dataclasses import dataclass, field
from typing import Any, Dict, List

from domain.threat import Threat


@dataclass
class CollectionResult:
    """
    Represents the result of collecting threats from a threat intelligence source.

    Attributes:
        threats: Normalized threats extracted from the external source.
        metadata: Source-specific collection metadata (version, timestamp,
                  total results, etc.). we don't need to lose this precious info, we could use it later on in feeding the LLM model
    """

    threats: List[Threat] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)