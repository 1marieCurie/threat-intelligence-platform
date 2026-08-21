from __future__ import annotations

import pytest

from application.models.url_analysis import (
    URLThreatClassification,
)
from application.models.url_features import (
    URLFeatureVector,
)
from application.services.analyze_url_service import (
    AnalyzeURLService,
)
from application.services.canonical_url_normalizer import (
    CanonicalURLNormalizationError,
)


class FakeURLThreatClassifier:
    def __init__(
        self,
        *,
        threat_class: str,
        confidence: float,
    ) -> None:
        self._result = (
            URLThreatClassification(
                threat_class=threat_class, # pyright: ignore[reportArgumentType]
                confidence=confidence,
                model_version=(
                    "test-model"
                ),
            )
        )

        self.received_features: (
            URLFeatureVector | None
        ) = None

    def classify(
        self,
        features: URLFeatureVector,
    ) -> URLThreatClassification:
        self.received_features = (
            features
        )

        return self._result


@pytest.mark.parametrize(
    (
        "threat_class",
        "expected_verdict",
    ),
    [
        (
            "benign",
            "benign",
        ),
        (
            "phishing",
            "malicious",
        ),
        (
            "malware",
            "malicious",
        ),
    ],
)
def test_analyze_url_maps_model_class_to_verdict(
    threat_class: str,
    expected_verdict: str,
) -> None:
    classifier = (
        FakeURLThreatClassifier(
            threat_class=threat_class,
            confidence=0.91,
        )
    )

    service = AnalyzeURLService(
        classifier=classifier
    )

    result = service.analyze(
        "https://example.com/login"
    )

    assert (
        result.verdict
        == expected_verdict
    )

    assert (
        result.threat_class
        == threat_class
    )

    assert result.confidence == 0.91

    assert (
        result.model_version
        == "test-model"
    )


def test_analyze_url_uses_existing_feature_pipeline(
) -> None:
    classifier = (
        FakeURLThreatClassifier(
            threat_class="benign",
            confidence=0.88,
        )
    )

    service = AnalyzeURLService(
        classifier=classifier
    )

    service.analyze(
        " HTTPS://Example.COM:443/login "
    )

    features = (
        classifier.received_features
    )

    assert features is not None

    assert (
        features.feature_set_version
        == "2.0.0"
    )

    assert (
        features.url_length
        == len(
            "https://example.com/login"
        )
    )


def test_analyze_url_rejects_invalid_url_before_classification(
) -> None:
    classifier = (
        FakeURLThreatClassifier(
            threat_class="benign",
            confidence=0.90,
        )
    )

    service = AnalyzeURLService(
        classifier=classifier
    )

    with pytest.raises(
        CanonicalURLNormalizationError
    ):
        service.analyze(
            "not-a-valid-url"
        )

    assert (
        classifier.received_features
        is None
    )