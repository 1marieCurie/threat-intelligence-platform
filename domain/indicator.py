from dataclasses import dataclass, field
from typing import Any, Dict, Optional


@dataclass(frozen=True)
class Indicator:
    """
    Normalized cyber threat indicator.

    An Indicator represents an observable value associated with
    a threat, such as a URL, IP address, domain name or file hash.

    It is a domain value object:
    - it has no independent identity;
    - it is immutable;
    - equality is based on its values.
    """

    # Indicator category.
    #
    # Examples:
    # url, domain, ipv4, ipv6, cidr,
    # md5, sha1, sha256, email
    type: str

    # Actual observable value.
    value: str

    # Optional confidence score normalized between 0.0 and 1.0.
    confidence: Optional[float] = None

    # Additional contextual information that does not belong
    # to the normalized core fields.
    metadata: Dict[str, Any] = field(
        default_factory=dict,
        compare=False,
        hash=False,
    )

    def __post_init__(self) -> None:
        normalized_type = self.type.strip().lower()
        normalized_value = self.value.strip()

        if not normalized_type:
            raise ValueError("Indicator type must not be empty.")

        if not normalized_value:
            raise ValueError("Indicator value must not be empty.")

        if self.confidence is not None and not (
            0.0 <= self.confidence <= 1.0
        ):
            raise ValueError(
                "Indicator confidence must be between 0.0 and 1.0."
            )

        object.__setattr__(self, "type", normalized_type)
        object.__setattr__(self, "value", normalized_value)