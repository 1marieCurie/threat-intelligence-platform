from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Protocol


@dataclass(
    frozen=True,
    slots=True,
)
class CisaKevApplicationKey:
    """
    Clé de recherche normalisée d'une application
    dans le catalogue CISA KEV.

    vendor_project correspond au vendor normalisé.
    product correspond au nom produit normalisé.
    """

    vendor_project: str
    product: str


@dataclass(
    frozen=True,
    slots=True,
)
class CisaKevApplicationCandidate:
    """
    Candidat CISA KEV retourné par le reader.

    Les valeurs normalisées servent au matching
    déterministe avec SoftwareComponent.
    """

    cve_id: str

    vendor_project: str
    product: str

    normalized_vendor_project: str
    normalized_product: str


class CisaKevApplicationReadRepository(
    Protocol
):
    """
    Port de lecture du catalogue CISA KEV utilisé
    par le moteur d'exposition.

    Ce port est distinct du repository d'ingestion
    CISA existant.

    L'implémentation doit :
    - travailler en batch ;
    - utiliser le snapshot CISA courant ;
    - éviter toute requête par application ;
    - ne faire aucun fuzzy matching.
    """

    def find_candidates(
        self,
        *,
        application_keys: Iterable[
            CisaKevApplicationKey
        ],
    ) -> tuple[
        CisaKevApplicationCandidate,
        ...,
    ]:
        ...