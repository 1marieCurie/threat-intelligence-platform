from __future__ import annotations

from collections.abc import Iterable
from typing import Any, Protocol


class CWECatalogClient(Protocol):
    """
    Port d'accès au catalogue officiel MITRE CWE.
    """

    def fetch_version(
        self,
    ) -> dict[str, Any]:
        """
        Retourne les métadonnées de version du catalogue.
        """
        ...

    def fetch_weaknesses(
        self,
        cwe_ids: Iterable[str | int],
    ) -> dict[str, Any]:
        """
        Retourne les faiblesses correspondant aux identifiants.
        """
        ...