from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import (
    Iterable,
    Mapping,
)
from datetime import date

from application.models.epss_snapshot import (
    EPSSSnapshot,
)


class EPSSProviderError(RuntimeError):
    """
    Erreur générique lors de la récupération de données EPSS.

    Cette exception évite de propager des dépendances techniques,
    comme requests, jusque dans la couche applicative.
    """


class EPSSProviderUnavailableError(
    EPSSProviderError
):
    """
    Le fournisseur EPSS est temporairement indisponible.

    Exemples :
    - timeout ;
    - erreur réseau ;
    - réponse HTTP 5xx.
    """


class InvalidEPSSResponseError(
    EPSSProviderError
):
    """
    La réponse du fournisseur EPSS est invalide ou inexploitable.

    Exemples :
    - JSON mal formé ;
    - structure inattendue ;
    - score ou date invalide.
    """


class EPSSProvider(ABC):
    """
    Port de récupération des scores EPSS.

    Le port retourne des valeurs applicatives typées et ne
    révèle ni HTTP, ni JSON, ni la stratégie de batching
    utilisée par l'adaptateur.
    """

    @abstractmethod
    def fetch_by_cve_ids(
        self,
        cve_ids: Iterable[str],
        *,
        score_date: date | None = None,
    ) -> Mapping[str, EPSSSnapshot]:
        """
        Récupère les snapshots EPSS associés aux CVE demandés.

        Les clés retournées doivent être des identifiants CVE
        normalisés en majuscules.

        Les CVE absents de la réponse du fournisseur sont omis
        du mapping.

        Args:
            cve_ids:
                Identifiants CVE à rechercher.

            score_date:
                Date historique optionnelle. Lorsque la valeur
                est absente, le dernier score disponible est
                demandé.

        Returns:
            Mapping entre chaque identifiant CVE disponible et
            son snapshot EPSS.
        """