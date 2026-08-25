from __future__ import annotations

from unittest.mock import Mock

from fastapi.testclient import (
    TestClient,
)

from application.models.url_analysis import (
    URLAnalysisResult,
)
from application.security.machine_api_key_authenticator import (
    MachineApiKeyAuthenticator,
)
from application.services.analyze_url_service import (
    AnalyzeURLService,
)
from application.services.import_machine_inventory_service import (
    ImportMachineInventoryService,
)
from infrastructure.api.app import (
    create_app,
)


def test_public_url_analysis_requires_no_authentication(
) -> None:
    import_service = Mock(
        spec=ImportMachineInventoryService
    )

    authenticator = Mock(
        spec=MachineApiKeyAuthenticator
    )

    analyze_service = Mock(
        spec=AnalyzeURLService
    )

    analyze_service.analyze.return_value = (
        URLAnalysisResult(
            verdict="benign",
            threat_class="benign",
            confidence=0.97,
            model_version="test-model",
        )
    )

    app = create_app(
        import_service=import_service,
        authenticator=authenticator,
        analyze_url_service=analyze_service,
    )

    client = TestClient(app)

    response = client.post(
        "/api/v1/public/url-analysis",
        json={
            "url": "https://example.com",
        },
    )

    assert response.status_code == 200
    assert response.json() == {
        "verdict": "benign",
        "threat_class": "benign",
        "confidence": 0.97,
        "model_version": "test-model",
    }

    analyze_service.analyze.assert_called_once_with(
        "https://example.com"
    )
