from __future__ import annotations

from dataclasses import FrozenInstanceError
from datetime import date, datetime

import pytest

from application.models.epss_snapshot import (
    EPSSSnapshot,
)


def test_constructor_stores_valid_values() -> None:
    snapshot = EPSSSnapshot(
        score=0.85,
        percentile=0.97,
        score_date=date(
            2026,
            7,
            30,
        ),
        api_version="v2026.07",
    )

    assert snapshot.score == 0.85
    assert snapshot.percentile == 0.97
    assert snapshot.score_date == date(
        2026,
        7,
        30,
    )
    assert snapshot.api_version == "v2026.07"


def test_constructor_converts_integers_to_floats() -> None:
    snapshot = EPSSSnapshot(
        score=1,
        percentile=0,
        score_date=date(
            2026,
            7,
            30,
        ),
    )

    assert snapshot.score == 1.0
    assert snapshot.percentile == 0.0

    assert isinstance(
        snapshot.score,
        float,
    )
    assert isinstance(
        snapshot.percentile,
        float,
    )


def test_constructor_normalizes_api_version() -> None:
    snapshot = EPSSSnapshot(
        score=0.5,
        percentile=0.8,
        score_date=date(
            2026,
            7,
            30,
        ),
        api_version="  v2026.07  ",
    )

    assert snapshot.api_version == "v2026.07"


def test_snapshot_is_immutable() -> None:
    snapshot = EPSSSnapshot(
        score=0.5,
        percentile=0.8,
        score_date=date(
            2026,
            7,
            30,
        ),
    )

    with pytest.raises(
        FrozenInstanceError,
    ):
        snapshot.score = 0.9  # type: ignore[misc]


@pytest.mark.parametrize(
    (
        "field_name",
        "value",
    ),
    [
        (
            "score",
            -0.01,
        ),
        (
            "score",
            1.01,
        ),
        (
            "percentile",
            -0.01,
        ),
        (
            "percentile",
            1.01,
        ),
    ],
)
def test_constructor_rejects_values_outside_probability_range(
    field_name: str,
    value: float,
) -> None:
    arguments = {
        "score": 0.5,
        "percentile": 0.8,
        "score_date": date(
            2026,
            7,
            30,
        ),
    }

    arguments[field_name] = value

    with pytest.raises(
        ValueError,
        match=(
            rf"{field_name} must be "
            r"between 0 and 1"
        ),
    ):
        EPSSSnapshot(
            **arguments,  # type: ignore[arg-type]
        )


@pytest.mark.parametrize(
    (
        "field_name",
        "value",
    ),
    [
        (
            "score",
            float("nan"),
        ),
        (
            "score",
            float("inf"),
        ),
        (
            "score",
            float("-inf"),
        ),
        (
            "percentile",
            float("nan"),
        ),
        (
            "percentile",
            float("inf"),
        ),
        (
            "percentile",
            float("-inf"),
        ),
    ],
)
def test_constructor_rejects_non_finite_values(
    field_name: str,
    value: float,
) -> None:
    arguments = {
        "score": 0.5,
        "percentile": 0.8,
        "score_date": date(
            2026,
            7,
            30,
        ),
    }

    arguments[field_name] = value

    with pytest.raises(
        ValueError,
        match=rf"{field_name} must be finite",
    ):
        EPSSSnapshot(
            **arguments,  # type: ignore[arg-type]
        )


@pytest.mark.parametrize(
    (
        "field_name",
        "value",
    ),
    [
        (
            "score",
            True,
        ),
        (
            "score",
            "0.5",
        ),
        (
            "score",
            None,
        ),
        (
            "percentile",
            False,
        ),
        (
            "percentile",
            "0.8",
        ),
        (
            "percentile",
            None,
        ),
    ],
)
def test_constructor_rejects_invalid_probability_types(
    field_name: str,
    value: object,
) -> None:
    arguments = {
        "score": 0.5,
        "percentile": 0.8,
        "score_date": date(
            2026,
            7,
            30,
        ),
    }

    arguments[field_name] = value

    with pytest.raises(
        TypeError,
        match=rf"{field_name} must be a number",
    ):
        EPSSSnapshot(
            **arguments,  # type: ignore[arg-type]
        )


@pytest.mark.parametrize(
    "invalid_date",
    [
        "2026-07-30",
        datetime(
            2026,
            7,
            30,
        ),
        None,
    ],
)
def test_constructor_rejects_invalid_score_date(
    invalid_date: object,
) -> None:
    with pytest.raises(
        TypeError,
        match="score_date must be a date",
    ):
        EPSSSnapshot(
            score=0.5,
            percentile=0.8,
            score_date=invalid_date,  # type: ignore[arg-type]
        )


def test_constructor_accepts_missing_api_version() -> None:
    snapshot = EPSSSnapshot(
        score=0.5,
        percentile=0.8,
        score_date=date(
            2026,
            7,
            30,
        ),
        api_version=None,
    )

    assert snapshot.api_version is None


@pytest.mark.parametrize(
    "invalid_version",
    [
        "",
        "   ",
        "version-longer-than-20",
    ],
)
def test_constructor_rejects_invalid_api_version_value(
    invalid_version: str,
) -> None:
    with pytest.raises(
        ValueError,
    ):
        EPSSSnapshot(
            score=0.5,
            percentile=0.8,
            score_date=date(
                2026,
                7,
                30,
            ),
            api_version=invalid_version,
        )


@pytest.mark.parametrize(
    "invalid_version",
    [
        2026,
        True,
        [],
    ],
)
def test_constructor_rejects_invalid_api_version_type(
    invalid_version: object,
) -> None:
    with pytest.raises(
        TypeError,
        match=(
            "api_version must be "
            "a string or None"
        ),
    ):
        EPSSSnapshot(
            score=0.5,
            percentile=0.8,
            score_date=date(
                2026,
                7,
                30,
            ),
            api_version=invalid_version,  # type: ignore[arg-type]
        )