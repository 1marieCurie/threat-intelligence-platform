from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Protocol


@dataclass(
    frozen=True,
    slots=True,
)
class GitHubAdvisoryPackageKey:
    ecosystem: str
    package_name: str


@dataclass(
    frozen=True,
    slots=True,
)
class GitHubAdvisoryPackageCandidate:
    ghsa_id: str
    cve_id: str | None

    ecosystem: str
    package_name: str

    vulnerable_version_range: str
    first_patched_version: str | None

    severity: str | None


class GitHubAdvisoryPackageReadRepository(
    Protocol
):
    """
    Port de lecture utilisé par le moteur
    d'exposition aux vulnérabilités.

    Ce port est distinct du repository
    d'ingestion GitHub Advisory.
    """

    def find_candidates(
        self,
        *,
        package_keys: Iterable[
            GitHubAdvisoryPackageKey
        ],
    ) -> tuple[
        GitHubAdvisoryPackageCandidate,
        ...,
    ]:
        """
        Retourne en batch les advisories candidats
        pour les packages demandés.

        L'implémentation ne doit pas effectuer
        une requête SQL par package.
        """
        ...