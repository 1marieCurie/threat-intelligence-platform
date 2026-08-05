from __future__ import annotations

import pytest

from domain.cwe_identifier import (
    normalize_cwe_id,
    normalize_cwe_ids,
)


@pytest.mark.parametrize(
    (
        "value",
        "expected",
    ),
    [
        (
            "CWE-79",
            "CWE-79",
        ),
        (
            " cwe-89 ",
            "CWE-89",
        ),
        (
            "94",
            "CWE-94",
        ),
        (
            "CWE-079",
            "CWE-79",
        ),
    ],
)
def test_normalizes_source_cwe_identifier(
    value: object,
    expected: str,
) -> None:
    assert normalize_cwe_id(
        value
    ) == expected


@pytest.mark.parametrize(
    "value",
    [
        None,
        "",
        "CWE-0",
        "CWE-A",
        "CWE--79",
        object(),
        True,
        79,
    ],
)
def test_ignores_invalid_source_cwe_identifier(
    value: object,
) -> None:
    assert normalize_cwe_id(
        value
    ) is None


def test_normalizes_and_deduplicates_collection(
) -> None:
    assert normalize_cwe_ids(
        [
            "CWE-79",
            "cwe-89",
            "79",
            "invalid",
            None,
            "CWE-089",
        ]
    ) == (
        "CWE-79",
        "CWE-89",
    )


def test_none_collection_becomes_empty_tuple(
) -> None:
    assert normalize_cwe_ids(
        None
    ) == ()


def test_rejects_single_string_collection(
) -> None:
    with pytest.raises(
        TypeError,
        match=(
            "cwe_ids must be an iterable "
            "of identifiers"
        ),
    ):
        normalize_cwe_ids(
            "CWE-79"
        )