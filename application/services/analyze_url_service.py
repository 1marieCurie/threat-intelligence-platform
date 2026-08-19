from __future__ import annotations

from application.models.url_analysis import (
    URLAnalysisResult,
)
from application.ports.outbound.url_threat_classifier import (
    URLThreatClassifier,
)
from application.services.canonical_url_normalizer import (
    CanonicalURLNormalizer,
)
from application.services.url_feature_extractor import (
    URLFeatureExtractor,
)


class AnalyzeURLService:
    """
    Orchestre l'analyse temps réel d'une URL.

    Pipeline :

    URL brute
        -> canonicalisation
        -> extraction des features
        -> classification ML
        -> verdict frontend

    Aucune analyse URL n'est persistée en V1.
    """

    def __init__(
        self,
        *,
        classifier: URLThreatClassifier,
        normalizer: (
            CanonicalURLNormalizer | None
        ) = None,
        feature_extractor: (
            URLFeatureExtractor | None
        ) = None,
    ) -> None:
        if classifier is None:
            raise ValueError(
                "classifier must not be None"
            )

        self._classifier = classifier

        self._normalizer = (
            CanonicalURLNormalizer()
            if normalizer is None
            else normalizer
        )

        self._feature_extractor = (
            URLFeatureExtractor()
            if feature_extractor is None
            else feature_extractor
        )

    def analyze(
        self,
        url: str,
    ) -> URLAnalysisResult:
        canonical_identity = (
            self._normalizer.normalize(
                url
            )
        )

        features = (
            self._feature_extractor.extract(
                canonical_identity.canonical_value
            )
        )

        classification = (
            self._classifier.classify(
                features
            )
        )

        verdict = (
            "benign"
            if classification.threat_class
            == "benign"
            else "malicious"
        )

        return URLAnalysisResult(
            verdict=verdict,
            threat_class=(
                classification.threat_class
            ),
            confidence=(
                classification.confidence
            ),
            model_version=(
                classification.model_version
            ),
        )