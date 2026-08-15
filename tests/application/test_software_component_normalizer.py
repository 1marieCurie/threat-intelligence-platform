from __future__ import annotations

import pytest

from application.services.software_component_normalizer import (
    SoftwareComponentNormalizer,
)



def test_normalizes_application_name_and_vendor() -> None:
    normalizer = (
        SoftwareComponentNormalizer()
    )

    result = normalizer.normalize(
        component_type="application",
        name="  Microsoft   Edge ",
        vendor=" Microsoft   Corporation ",
        ecosystem=None,
    )

    assert (
        result.normalized_name
        == "microsoft edge"
    )

    assert (
        result.normalized_vendor
        == "microsoft corporation"
    )

    assert (
        result.normalizer_version
        == "1.0.0"
    )


def test_normalizes_pypi_package_name() -> None:
    normalizer = (
        SoftwareComponentNormalizer()
    )

    result = normalizer.normalize(
        component_type="package",
        name="Requests_Security.Test",
        vendor=None,
        ecosystem="PyPI",
    )

    assert (
        result.normalized_name
        == "requests-security-test"
    )

    assert (
        result.normalized_vendor
        is None
    )


def test_normalizes_scoped_npm_package() -> None:
    normalizer = (
        SoftwareComponentNormalizer()
    )

    result = normalizer.normalize(
        component_type="package",
        name="@Scope/Package",
        vendor=None,
        ecosystem="NPM",
    )

    assert (
        result.normalized_name
        == "@scope/package"
    )


def test_rejects_unknown_package_ecosystem() -> None:
    normalizer = (
        SoftwareComponentNormalizer()
    )

    with pytest.raises(
        ValueError,
        match="package ecosystem",
    ):
        normalizer.normalize(
            component_type="package",
            name="example",
            vendor=None,
            ecosystem="unknown",
        )


def test_rejects_application_ecosystem() -> None:
    normalizer = (
        SoftwareComponentNormalizer()
    )

    with pytest.raises(
        ValueError,
        match="application ecosystem",
    ):
        normalizer.normalize(
            component_type="application",
            name="Example",
            vendor="Vendor",
            ecosystem="pypi",
        )