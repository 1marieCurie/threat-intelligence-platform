from __future__ import annotations

import math
from collections import Counter
from urllib.parse import urlsplit

import pytest

from application.models.url_features import (
    URLFeatureVector,
)
from application.services.canonical_url_normalizer import (
    CanonicalURLNormalizer,
)
from application.services.url_feature_extractor import (
    URLFeatureExtractionError,
    URLFeatureExtractor,
)


EXPECTED_FEATURE_NAMES = (
    "url_length",
    "hostname_length",
    "dot_count",
    "hyphen_count",
    "digit_count",
    "special_char_count",
    "path_segment_count",
    "hostname_entropy",
    "mean_hostname_label_length",
    "path_to_url_length_ratio",
    "special_char_ratio",
    "path_length_special_char_ratio_product",
    "path_segment_count_special_char_ratio_product",
)


def _normalized_product(
    left: int | float,
    right: int | float,
) -> float:
    return (
        left
        / (
            1.0
            + abs(left)
        )
    ) * (
        right
        / (
            1.0
            + abs(right)
        )
    )


def _expected_entropy(
    value: str,
) -> float:
    frequencies = Counter(
        value
    )

    value_length = len(
        value
    )

    return -sum(
        (
            count
            / value_length
        )
        * math.log2(
            count
            / value_length
        )
        for count in frequencies.values()
    )


def test_feature_schema_matches_frozen_v1() -> None:
    assert (
        URLFeatureVector.FEATURE_NAMES
        == EXPECTED_FEATURE_NAMES
    )

    assert (
        len(
            URLFeatureVector.FEATURE_NAMES
        )
        == 13
    )


def test_extracts_feature_set_v1() -> None:
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

    canonical_value = (
        identity.canonical_value
    )

    parsed = urlsplit(
        canonical_value
    )

    hostname = (
        parsed.hostname
        or ""
    ).lower()

    path = (
        parsed.path
        or "/"
    )

    features = extractor.extract(
        canonical_value
    )

    url_length = len(
        canonical_value
    )

    path_length = len(
        path
    )

    special_char_count = sum(
        not character.isalnum()
        for character in canonical_value
    )

    special_char_ratio = (
        special_char_count
        / url_length
    )

    path_segment_count = sum(
        1
        for segment in path.split(
            "/"
        )
        if segment
    )

    labels = [
        label
        for label in hostname.split(
            "."
        )
        if label
    ]

    expected_mean_label_length = (
        sum(
            len(label)
            for label in labels
        )
        / len(labels)
    )

    assert (
        features.feature_set_version
        == "2.0.0"
    )

    assert (
        features.url_length
        == url_length
    )

    assert (
        features.hostname_length
        == len(hostname)
    )

    assert (
        features.dot_count
        == canonical_value.count(".")
    )

    assert (
        features.hyphen_count
        == canonical_value.count("-")
    )

    assert (
        features.digit_count
        == sum(
            character.isdigit()
            for character in canonical_value
        )
    )

    assert (
        features.special_char_count
        == special_char_count
    )

    assert (
        features.path_segment_count
        == path_segment_count
    )

    assert (
        features.hostname_entropy
        == pytest.approx(
            _expected_entropy(
                hostname
            )
        )
    )

    assert (
        features.mean_hostname_label_length
        == pytest.approx(
            expected_mean_label_length
        )
    )

    assert (
        features.path_to_url_length_ratio
        == pytest.approx(
            path_length
            / url_length
        )
    )

    assert (
        features.special_char_ratio
        == pytest.approx(
            special_char_ratio
        )
    )

    assert (
        features.path_length_special_char_ratio_product
        == pytest.approx(
            _normalized_product(
                path_length,
                special_char_ratio,
            )
        )
    )

    assert (
        features.path_segment_count_special_char_ratio_product
        == pytest.approx(
            _normalized_product(
                path_segment_count,
                special_char_ratio,
            )
        )
    )


def test_excluded_features_are_not_exposed() -> None:
    normalizer = (
        CanonicalURLNormalizer()
    )

    extractor = (
        URLFeatureExtractor()
    )

    identity = normalizer.normalize(
        "http://192.0.2.10:8080/"
        "download/file.exe"
        "?token=value"
    )

    features = extractor.extract(
        identity.canonical_value
    )

    excluded_features = (
        "path_length",
        "query_length",
        "fragment_length",
        "query_parameter_count",
        "has_ip_address",
        "has_https",
        "has_non_default_port",
        "has_punycode",
        "has_percent_encoding",
    )

    for feature_name in excluded_features:
        assert not hasattr(
            features,
            feature_name,
        )


def test_root_path_is_handled_deterministically() -> None:
    normalizer = (
        CanonicalURLNormalizer()
    )

    extractor = (
        URLFeatureExtractor()
    )

    identity = normalizer.normalize(
        "https://example.com"
    )

    features = extractor.extract(
        identity.canonical_value
    )

    assert (
        features.path_segment_count
        == 0
    )

    assert (
        features.path_to_url_length_ratio
        > 0.0
    )

    assert (
        features.path_segment_count_special_char_ratio_product
        == pytest.approx(
            0.0
        )
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


def test_rejects_unsupported_scheme() -> None:
    extractor = (
        URLFeatureExtractor()
    )

    with pytest.raises(
        URLFeatureExtractionError
    ):
        extractor.extract(
            "ftp://example.com/file"
        )


def test_error_does_not_expose_canonical_url() -> None:
    extractor = (
        URLFeatureExtractor()
    )

    sensitive_value = (
        "https://example.com/"
        + "secret-token-" * 500
    )

    with pytest.raises(
        URLFeatureExtractionError
    ) as error:
        extractor.extract(
            sensitive_value
        )

    assert (
        "secret-token"
        not in str(
            error.value
        )
    )