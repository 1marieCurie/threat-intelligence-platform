from __future__ import annotations

from dataclasses import dataclass
from typing import Literal


URLThreatClass = Literal[
    "benign",
    "phishing",
    "malware",
]

URLVerdict = Literal[
    "benign",
    "malicious",
]


@dataclass(
    frozen=True,
    slots=True,
)
class URLThreatClassification:
    """
    Résultat brut fourni par le classifieur ML.

    threat_class conserve la classe réelle du modèle :
    benign | phishing | malware.

    confidence correspond à la probabilité associée
    à la classe prédite.
    """

    threat_class: URLThreatClass
    confidence: float
    model_version: str

    def __post_init__(
        self,
    ) -> None:
        if self.threat_class not in {
            "benign",
            "phishing",
            "malware",
        }:
            raise ValueError(
                "Unsupported URL threat class"
            )

        if (
            isinstance(
                self.confidence,
                bool,
            )
            or not isinstance(
                self.confidence,
                (int, float),
            )
        ):
            raise TypeError(
                "confidence must be numeric"
            )

        normalized_confidence = float(
            self.confidence
        )

        if not (
            0.0
            <= normalized_confidence
            <= 1.0
        ):
            raise ValueError(
                "confidence must be between 0 and 1"
            )

        if not isinstance(
            self.model_version,
            str,
        ):
            raise TypeError(
                "model_version must be a string"
            )

        normalized_model_version = (
            self.model_version.strip()
        )

        if not normalized_model_version:
            raise ValueError(
                "model_version must not be empty"
            )

        object.__setattr__(
            self,
            "confidence",
            normalized_confidence,
        )

        object.__setattr__(
            self,
            "model_version",
            normalized_model_version,
        )


@dataclass(
    frozen=True,
    slots=True,
)
class URLAnalysisResult:
    """
    Résultat applicatif retournable à l'API.

    verdict simplifie les trois classes ML pour
    l'affichage frontend :

    benign   -> benign
    phishing -> malicious
    malware  -> malicious
    """

    verdict: URLVerdict
    threat_class: URLThreatClass
    confidence: float
    model_version: str