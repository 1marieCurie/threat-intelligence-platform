from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable

from domain.cwe_weakness import CWEWeakness


class CWERepository(ABC):
    """
    Port de lecture du catalogue officiel CWE.

    Les services d'enrichissement dépendent uniquement de ce
    contrat en lecture.
    """

    @abstractmethod
    def find_by_id(
        self,
        cwe_id: str,
    ) -> CWEWeakness | None:
        """
        Retourne une faiblesse officielle ou None.
        """

    def find_many_by_ids(
        self,
        cwe_ids: Iterable[str],
    ) -> list[CWEWeakness]:
        """
        Implémentation générique multi-identifiants.

        Les repositories persistants doivent surcharger cette méthode
        afin d'utiliser une seule requête SQL.
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


class WritableCWERepository(CWERepository):
    """
    Port du catalogue CWE disposant des opérations d'écriture.

    Cette séparation évite d'imposer une méthode d'écriture aux
    repositories de lecture utilisés dans les tests ou adapters API.
    """

    @abstractmethod
    def upsert_many(
        self,
        weaknesses: Iterable[CWEWeakness],
    ) -> int:
        """
        Insère ou actualise plusieurs entrées CWE.

        Retourne le nombre d'identifiants uniques pris en charge.
        """