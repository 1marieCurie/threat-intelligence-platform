from __future__ import annotations

from typing import Any, Protocol


class PayloadHasher(Protocol):
    def hash(
        self,
        payload: dict[str, Any],
    ) -> str:
        """Retourne une empreinte SHA-256 déterministe du payload."""
        ...