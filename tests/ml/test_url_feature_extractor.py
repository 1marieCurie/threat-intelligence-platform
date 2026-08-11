from __future__ import annotations

import pytest

from application.services.canonical_url_normalizer import (
    CanonicalURLNormalizer,
)
from application.services.url_feature_extractor import (
    URLFeatureExtractionError,
    URLFeatureExtractor,
)


def test_extracts_structural_features() -> None:
    normalizer = (
        CanonicalURLNormalizer()
    )

    extractor = (
        URLFeatureExtractor()
    )

    identity = normalizer.normalize(
        "HTTPS://Example.COM:8443/"
        "account/login-123"
        "?page=2&token=abc%20def"
        "#section"
    )

    features = extractor.extract(
        identity.canonical_value
    )

    assert (
        features.feature_set_version
        == "1.0.0"
    )

    assert (
        features.hostname_length
        == len("example.com")
    )

    assert (
        features.path_segment_count
        == 2
    )

    assert (
        features.query_parameter_count
        == 2
    )

    assert features.has_https is True

    assert (
        features.has_non_default_port
        is True
    )

    assert (
        features.has_percent_encoding
        is True
    )

    assert (
        features.has_ip_address
        is False
    )


def test_detects_ip_address() -> None:
    normalizer = (
        CanonicalURLNormalizer()
    )

    extractor = (
        URLFeatureExtractor()
    )

    identity = normalizer.normalize(
        "http://192.0.2.10/download/file.exe"
    )

    features = extractor.extract(
        identity.canonical_value
    )

    assert (
        features.has_ip_address
        is True
    )


def test_detects_punycode_hostname() -> None:
    normalizer = (
        CanonicalURLNormalizer()
    )

    extractor = (
        URLFeatureExtractor()
    )

    identity = normalizer.normalize(
        "https://bücher.example/path"
    )

    features = extractor.extract(
        identity.canonical_value
    )

    assert (
        features.has_punycode
        is True
    )


def test_rejects_empty_value() -> None:
    extractor = (
        URLFeatureExtractor()
    )

    with pytest.raises(
        URLFeatureExtractionError
    ):
        extractor.extract(
            ""
        )


def test_feature_extraction_is_deterministic() -> None:
    normalizer = (
        CanonicalURLNormalizer()
    )

    extractor = (
        URLFeatureExtractor()
    )

    identity = normalizer.normalize(
        "https://example.com/a/b?id=123"
    )

    first = extractor.extract(
        identity.canonical_value
    )

    second = extractor.extract(
        identity.canonical_value
    )

    assert first == second