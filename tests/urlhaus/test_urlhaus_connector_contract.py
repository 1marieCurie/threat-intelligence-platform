from __future__ import annotations

from infrastructure.adapters.outbound.urlhaus_connector import (
    URLhausConnector,
)


def test_connector_exposes_canonical_source_url(
) -> None:
    connector = URLhausConnector(
        auth_key="test-auth-key",
    )

    source_url = (
        connector.canonical_source_url
    )

    assert source_url == (
        "https://urlhaus-api.abuse.ch/"
        "v1/urls/recent/"
    )

    assert "test-auth-key" not in (
        source_url
    )


def test_canonical_source_url_uses_injected_base_url(
) -> None:
    connector = URLhausConnector(
        auth_key="test-auth-key",
        base_url=(
            "https://example.test/v1"
        ),
    )

    assert (
        connector.canonical_source_url
        == (
            "https://example.test/"
            "v1/urls/recent/"
        )
    )