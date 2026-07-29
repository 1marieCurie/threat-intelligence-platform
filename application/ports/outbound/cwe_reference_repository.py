from __future__ import annotations

from typing import Protocol


class VulnerabilityCWEReferenceRepository(
    Protocol
):
    """
    Port de lecture des identifiants CWE référencés par les
    vulnérabilités normalisées.
    """

    def list_distinct_ids(
        self,
        *,
        limit: int,
    ) -> list[str]:
        """
        Retourne des identifiants CWE distincts et valides.
        """
        ...