from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable

from domain.cwe_weakness import CWEWeakness


class CWERepository(ABC):
    """
    Outbound persistence port for the official CWE catalog.
    """

    @abstractmethod
    def find_by_id(
        self,
        cwe_id: str,
    ) -> CWEWeakness | None:
        """
        Return one official CWE weakness or None when it is absent.
        """

    def find_many_by_ids(
        self,
        cwe_ids: Iterable[str],
    ) -> list[CWEWeakness]:
        """
        Default multi-ID implementation.

        Persistent repositories may override this method with a
        single optimized database query.
        """

        weaknesses: list[CWEWeakness] = []

        for cwe_id in cwe_ids:
            weakness = self.find_by_id(
                cwe_id
            )

            if weakness is not None:
                weaknesses.append(
                    weakness
                )

        return weaknesses