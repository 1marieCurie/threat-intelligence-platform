from __future__ import annotations

import pytest

from application.services.url_group_key_resolver import (
    URLGroupKeyResolutionError,
    URLGroupKeyResolver,
)


def test_resolves_standard_registered_domain(
) -> None:
    resolver = URLGroupKeyResolver()

    assert (
        resolver.resolve(
            "login.api.example.com"
        )
        == "example.com"
    )


def test_resolves_multi_label_public_suffix(
) -> None:
    resolver = URLGroupKeyResolver()

    assert (
        resolver.resolve(
            "secure.shop.example.co.uk"
        )
        == "example.co.uk"
    )


def test_private_suffix_is_supported(
) -> None:
    resolver = URLGroupKeyResolver()

    assert (
        resolver.resolve(
            "tenant.github.io"
        )
        == "tenant.github.io"
    )


def test_normalizes_ipv4_group_key(
) -> None:
    resolver = URLGroupKeyResolver()

    assert (
        resolver.resolve(
            "192.0.2.10"
        )
        == "192.0.2.10"
    )


def test_normalizes_ipv6_group_key(
) -> None:
    resolver = URLGroupKeyResolver()

    assert (
        resolver.resolve(
            "2001:0db8:0:0:0:0:0:1"
        )
        == "2001:db8::1"
    )


def test_normalizes_idna_hostname(
) -> None:
    resolver = URLGroupKeyResolver()

    group_key = resolver.resolve(
        "www.bücher.de"
    )

    assert (
        group_key
        == "xn--bcher-kva.de"
    )


def test_unknown_suffix_falls_back_to_hostname(
) -> None:
    resolver = URLGroupKeyResolver()

    assert (
        resolver.resolve(
            "subdomain.internal-test"
        )
        == "subdomain.internal-test"
    )


def test_resolution_is_deterministic(
) -> None:
    resolver = URLGroupKeyResolver()

    first = resolver.resolve(
        "Api.Example.CO.UK."
    )

    second = resolver.resolve(
        "api.example.co.uk"
    )

    assert first == second


def test_rejects_empty_hostname(
) -> None:
    resolver = URLGroupKeyResolver()

    with pytest.raises(
        URLGroupKeyResolutionError
    ):
        resolver.resolve(
            ""
        )


def test_error_does_not_echo_invalid_hostname(
) -> None:
    resolver = URLGroupKeyResolver()

    sensitive_value = (
        "secret-token."
        + ("a" * 300)
    )

    with pytest.raises(
        URLGroupKeyResolutionError
    ) as error:
        resolver.resolve(
            sensitive_value
        )

    assert (
        "secret-token"
        not in str(
            error.value
        )
    )