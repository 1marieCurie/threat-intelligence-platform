from __future__ import annotations

from unittest.mock import Mock

from fastapi.testclient import (
    TestClient,
)

from application.models.url_analysis import (
    URLAnalysisResult,
)
from application.ports.outbound.url_threat_classifier import (
    URLThreatClassifierInferenceError,
)
from application.security.machine_api_key_authenticator import (
    MachineApiKeyAuthenticator,
)
from application.services.analyze_url_service import (
    AnalyzeURLService,
)
from application.services.canonical_url_normalizer import (
    CanonicalURLNormalizationError,
)
from application.services.import_machine_inventory_service import (
    ImportMachineInventoryService,
)
from infrastructure.api.app import (
    create_app,
)


def _client(
) -> tuple[
    TestClient,
    Mock,
]:
    import_service = Mock(
        spec=ImportMachineInventoryService
    )

    authenticator = Mock(
        spec=MachineApiKeyAuthenticator
    )

    analyze_service = Mock(
        spec=AnalyzeURLService
    )

    app = create_app(
        import_service=import_service,
        authenticator=authenticator,
        analyze_url_service=(
            analyze_service
        ),
    )

    return (
        TestClient(app),
        analyze_service,
    )


def test_url_analysis_returns_model_result(
) -> None:
    client, service = _client()

    service.analyze.return_value = (
        URLAnalysisResult(
            verdict="malicious",
            threat_class="phishing",
            confidence=0.93,
            model_version=(
                "hgb-v3-hardened"
            ),
        )
    )

    response = client.post(
        "/api/v1/url-analysis",
        json={
            "url": (
                "https://example.com/login"
            )
        },
    )

    assert response.status_code == 200

    assert response.json() == {
        "verdict": "malicious",
        "threat_class": "phishing",
        "confidence": 0.93,
        "model_version": (
            "hgb-v3-hardened"
        ),
    }

    service.analyze.assert_called_once_with(
        "https://example.com/login"
    )


def test_url_analysis_rejects_invalid_url(
) -> None:
    client, service = _client()

    service.analyze.side_effect = (
        CanonicalURLNormalizationError(
            "URL scheme must be http or https"
        )
    )

    response = client.post(
        "/api/v1/url-analysis",
        json={
            "url": "not-a-url",
        },
    )

    assert response.status_code == 422

    assert response.json() == {
        "detail": (
            "URL scheme must be http or https"
        )
    }


def test_url_analysis_returns_503_on_ml_failure(
) -> None:
    client, service = _client()

    service.analyze.side_effect = (
        URLThreatClassifierInferenceError(
            "failure"
        )
    )

    response = client.post(
        "/api/v1/url-analysis",
        json={
            "url": (
                "https://example.com/"
            )
        },
    )

    assert response.status_code == 503

    assert response.json() == {
        "detail": (
            "URL analysis service is "
            "temporarily unavailable"
        )
    }