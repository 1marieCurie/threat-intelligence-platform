from __future__ import annotations

from hashlib import sha256

import pytest

from application.services.canonical_url_normalizer import (
    CanonicalURLNormalizationError,
    CanonicalURLNormalizer,
)


def test_normalizes_scheme_hostname_default_port_and_path(
) -> None:
    result = CanonicalURLNormalizer().normalize(
        " HTTPS://Example.COM.:443 "
    )

    assert result.canonical_value == (
        "https://example.com/"
    )

    assert result.hostname == (
        "example.com"
    )

    assert result.value_hash == sha256(
        result.canonical_value.encode(
            "utf-8"
        )
    ).hexdigest()

    assert (
        result.canonicalization_version
        == 1
    )


def test_preserves_path_query_order_encoding_and_fragment(
) -> None:
    result = CanonicalURLNormalizer().normalize(
        (
            "http://Example.com:8080/"
            "A%2fb?b=2&a=1#Section"
        )
    )

    assert result.canonical_value == (
        "http://example.com:8080/"
        "A%2fb?b=2&a=1#Section"
    )


def test_rejects_user_information(
) -> None:
    with pytest.raises(
        CanonicalURLNormalizationError,
        match="user information",
    ):
        CanonicalURLNormalizer().normalize(
            "http://User:Pass@Example.com/path"
        )


def test_normalizes_idna_hostname(
) -> None:
    result = CanonicalURLNormalizer().normalize(
        "https://TÉST.Example/path"
    )

    assert result.hostname == (
        "xn--tst-bma.example"
    )

    assert result.canonical_value == (
        "https://xn--tst-bma.example/path"
    )


def test_normalizes_ipv6_and_default_port(
) -> None:
    result = CanonicalURLNormalizer().normalize(
        "http://[2001:0db8::1]:80"
    )

    assert result.hostname == (
        "2001:db8::1"
    )

    assert result.canonical_value == (
        "http://[2001:db8::1]/"
    )


def test_keeps_non_default_port(
) -> None:
    result = CanonicalURLNormalizer().normalize(
        "https://example.com:8443/a"
    )

    assert result.canonical_value == (
        "https://example.com:8443/a"
    )


@pytest.mark.parametrize(
    "value",
    [
        "",
        " ",
        "ftp://example.com/file",
        "https:///missing-host",
        "https://example.com:",
        "https://example.com:invalid",
        "https://example.com/path with space",
        "https:\\\\example.com\\path",
        "https://@example.com/path",
    ],
)
def test_rejects_invalid_or_ambiguous_urls(
    value: str,
) -> None:
    with pytest.raises(
        CanonicalURLNormalizationError,
    ):
        CanonicalURLNormalizer().normalize(
            value
        )


def test_error_does_not_expose_ioc(
) -> None:
    malicious_value = (
        "https://secret-token.example/"
        "path with space"
    )

    with pytest.raises(
        CanonicalURLNormalizationError,
    ) as captured_error:
        CanonicalURLNormalizer().normalize(
            malicious_value
        )

    assert (
        "secret-token"
        not in str(
            captured_error.value
        )
    )


def test_normalization_is_deterministic(
) -> None:
    normalizer = CanonicalURLNormalizer()

    first = normalizer.normalize(
        "https://Example.com:443/path"
    )

    second = normalizer.normalize(
        "https://example.com/path"
    )

    assert first == second