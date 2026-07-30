from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable, Mapping

from application.models.epss_snapshot import (
    EPSSSnapshot,
)


class EPSSScoreRepository(ABC):
    """
    Port de lecture des enrichissements EPSS persistés.

    L'identité reste le CVE. Le repository retourne uniquement
    la valeur d'enrichissement EPSS associée à cet identifiant.
    """

    @abstractmethod
    def find_by_cve_id(
        self,
        cve_id: str,
    ) -> EPSSSnapshot | None:
        """
        Retourne le dernier snapshot EPSS connu pour un CVE.

        Retourne None lorsqu'aucun score n'est disponible.
        """

    def find_many_by_cve_ids(
        self,
        cve_ids: Iterable[str],
    ) -> dict[str, EPSSSnapshot]:
        """
        Retourne les snapshots indexés par identifiant CVE.

        Cette implémentation générique facilite les repositories
        en mémoire utilisés par les tests.

        Les repositories persistants doivent surcharger cette
        méthode afin d'exécuter une seule requête SQL.
        """
        if isinstance(
            cve_ids,
            (str, bytes),
        ):
            raise TypeError(
                "cve_ids must be an iterable of strings"
            )

        try:
            unique_cve_ids = list(
                dict.fromkeys(cve_ids)
            )
        except TypeError as error:
            raise TypeError(
                "cve_ids must be an iterable of strings"
            ) from error

        snapshots: dict[
            str,
            EPSSSnapshot,
        ] = {}

        for cve_id in unique_cve_ids:
            snapshot = self.find_by_cve_id(
                cve_id
            )

            if snapshot is not None:
                snapshots[cve_id] = snapshot

        return snapshots


class WritableEPSSScoreRepository(
    EPSSScoreRepository
):
    """
    Port EPSS permettant la persistance des scores.

    Les écritures sont séparées du contrat de lecture afin que
    l'enrichissement local ne dépende pas d'opérations inutiles.
    """

    @abstractmethod
    def upsert_many(
        self,
        snapshots_by_cve: Mapping[
            str,
            EPSSSnapshot,
        ],
    ) -> int:
        """
        Insère ou actualise plusieurs snapshots EPSS.

        La clé du mapping est l'identifiant CVE auquel le
        snapshot est associé.

        Un score existant ne doit pas être remplacé par un
        snapshot dont la date est plus ancienne.

        Retourne le nombre de CVE uniques pris en charge.
        """