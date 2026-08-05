from __future__ import annotations

from dataclasses import dataclass


@dataclass(
    frozen=True,
    slots=True,
)
class CanonicalURLIdentity:
    """
    Résultat immutable de la canonicalisation d'une URL.

    Cette projection ne contient aucune donnée propre à
    PhishTank ou URLhaus.
    """

    canonical_value: str
    value_hash: str
    hostname: str
    canonicalization_version: int