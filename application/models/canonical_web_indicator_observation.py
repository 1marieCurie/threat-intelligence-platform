from __future__ import annotations

from dataclasses import dataclass

from application.models.canonical_url_identity import (
    CanonicalURLIdentity,
)
from domain.web_indicator_observation import (
    WebIndicatorObservation,
)


@dataclass(
    frozen=True,
    slots=True,
)
class CanonicalWebIndicatorObservation:
    """
    Observation complète destinée à la corrélation Web.

    identity porte l'identité exacte de l'URL.
    observation porte la provenance de la source normalisée.
    """

    identity: CanonicalURLIdentity
    observation: WebIndicatorObservation

    def __post_init__(self) -> None:
        if not isinstance(
            self.identity,
            CanonicalURLIdentity,
        ):
            raise TypeError(
                "identity must be a "
                "CanonicalURLIdentity"
            )

        if not isinstance(
            self.observation,
            WebIndicatorObservation,
        ):
            raise TypeError(
                "observation must be a "
                "WebIndicatorObservation"
            )