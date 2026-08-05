from __future__ import annotations

from datetime import (
    UTC,
    datetime,
    timedelta,
    timezone,
)
from uuid import UUID, uuid4

import pytest

from domain.web_indicator_observation import (
    WebIndicatorObservation,
)


def _observation(
    **overrides: object,
) -> WebIndicatorObservation:
    values: dict[str, object] = {
        "source": "phishtank",
        "source_record_key": "12345",
        "normalized_record_id": uuid4(),
        "observed_at": datetime(
            2026,
            8,
            5,
            15,
            0,
            tzinfo=UTC,
        ),
        "normalizer_version": "1.0.1",
        "source_status": "verified",
        "is_active": True,
        "labels": (
            "phishing",
        ),
    }

    values.update(
        overrides
    )

    return WebIndicatorObservation(
        source=values["source"],  # type: ignore[arg-type]
        source_record_key=values[
            "source_record_key"
        ],  # type: ignore[arg-type]
        normalized_record_id=values[
            "normalized_record_id"
        ],  # type: ignore[arg-type]
        observed_at=values[
            "observed_at"
        ],  # type: ignore[arg-type]
        normalizer_version=values[
            "normalizer_version"
        ],  # type: ignore[arg-type]
        last_observed_at=values.get(
            "last_observed_at"
        ),  # type: ignore[arg-type]
        source_status=values.get(
            "source_status"
        ),  # type: ignore[arg-type]
        is_active=values.get(
            "is_active"
        ),  # type: ignore[arg-type]
        labels=values[
            "labels"
        ],  # type: ignore[arg-type]
    )


def test_normalizes_observation(
) -> None:
    local_timezone = timezone(
        timedelta(hours=2)
    )

    observation = _observation(
        source=" URLHAUS ",
        source_status=" ONLINE ",
        observed_at=datetime(
            2026,
            8,
            5,
            17,
            0,
            tzinfo=local_timezone,
        ),
        labels=(
            "malware_distribution",
            "malware_distribution",
        ),
    )

    assert observation.source == (
        "urlhaus"
    )

    assert observation.source_status == (
        "online"
    )

    assert observation.observed_at == (
        datetime(
            2026,
            8,
            5,
            15,
            0,
            tzinfo=UTC,
        )
    )

    assert observation.last_observed_at == (
        observation.observed_at
    )

    assert observation.labels == (
        "malware_distribution",
    )


def test_exposes_source_record_key(
) -> None:
    observation = _observation()

    assert observation.key == (
        "phishtank",
        "12345",
    )


def test_rejects_last_observation_before_first(
) -> None:
    observed_at = datetime(
        2026,
        8,
        5,
        tzinfo=UTC,
    )

    with pytest.raises(
        ValueError,
        match="last_observed_at",
    ):
        _observation(
            observed_at=observed_at,
            last_observed_at=(
                observed_at
                - timedelta(seconds=1)
            ),
        )


def test_rejects_nil_normalized_record_uuid(
) -> None:
    with pytest.raises(
        ValueError,
        match="nil UUID",
    ):
        _observation(
            normalized_record_id=UUID(
                int=0
            )
        )


def test_rejects_invalid_active_state(
) -> None:
    with pytest.raises(
        TypeError,
        match="is_active",
    ):
        _observation(
            is_active=1
        )


def test_rejects_invalid_label_format(
) -> None:
    with pytest.raises(
        ValueError,
        match="snake_case",
    ):
        _observation(
            labels=(
                "Malware Distribution",
            )
        )


def test_rejects_too_many_labels(
) -> None:
    with pytest.raises(
        ValueError,
        match="more than",
    ):
        _observation(
            labels=tuple(
                f"label_{index}"
                for index
                in range(21)
            )
        )