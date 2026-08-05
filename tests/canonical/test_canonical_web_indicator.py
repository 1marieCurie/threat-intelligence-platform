from __future__ import annotations

from datetime import (
    UTC,
    datetime,
    timedelta,
)
from hashlib import sha256
from uuid import uuid4

import pytest

from domain.canonical_web_indicator import (
    CanonicalWebIndicator,
)
from domain.web_indicator_observation import (
    WebIndicatorObservation,
)


CANONICAL_VALUE = (
    "https://example.com/login"
)

VALUE_HASH = sha256(
    CANONICAL_VALUE.encode(
        "utf-8"
    )
).hexdigest()


def _observation(
    *,
    source: str = "phishtank",
    source_record_key: str = "100",
    observed_at: datetime | None = None,
    labels: tuple[str, ...] = (
        "phishing",
    ),
) -> WebIndicatorObservation:
    first_seen_at = (
        observed_at
        or datetime(
            2026,
            8,
            5,
            10,
            0,
            tzinfo=UTC,
        )
    )

    return WebIndicatorObservation(
        source=source,
        source_record_key=(
            source_record_key
        ),
        normalized_record_id=uuid4(),
        observed_at=first_seen_at,
        last_observed_at=(
            first_seen_at
            + timedelta(hours=1)
        ),
        normalizer_version="1.0.0",
        source_status="online",
        is_active=True,
        labels=labels,
    )


def _indicator(
    *,
    observations: tuple[
        WebIndicatorObservation,
        ...,
    ] | None = None,
    value_hash: str = VALUE_HASH,
    created_at: datetime | None = None,
    updated_at: datetime | None = None,
) -> CanonicalWebIndicator:
    created = (
        created_at
        or datetime(
            2026,
            8,
            5,
            9,
            0,
            tzinfo=UTC,
        )
    )

    return CanonicalWebIndicator(
        id=uuid4(),
        canonical_value=(
            CANONICAL_VALUE
        ),
        value_hash=value_hash,
        hostname="example.com",
        observations=(
            observations
            if observations is not None
            else (
                _observation(),
            )
        ),
        created_at=created,
        updated_at=(
            updated_at
            or created
        ),
    )


def test_builds_source_neutral_indicator(
) -> None:
    first = _observation()

    second = _observation(
        source="urlhaus",
        source_record_key="200",
        observed_at=datetime(
            2026,
            8,
            6,
            10,
            0,
            tzinfo=UTC,
        ),
        labels=(
            "malware_distribution",
        ),
    )

    indicator = _indicator(
        observations=(
            first,
            second,
        )
    )

    assert indicator.indicator_type == (
        "url"
    )

    assert indicator.sources == (
        "phishtank",
        "urlhaus",
    )

    assert indicator.labels == (
        "phishing",
        "malware_distribution",
    )

    assert indicator.first_seen_at == (
        first.observed_at
    )

    assert indicator.last_seen_at == (
        second.last_observed_at
    )


def test_rejects_hash_not_matching_url(
) -> None:
    with pytest.raises(
        ValueError,
        match="does not match",
    ):
        _indicator(
            value_hash="0" * 64
        )


def test_rejects_missing_observation(
) -> None:
    with pytest.raises(
        ValueError,
        match="at least one observation",
    ):
        _indicator(
            observations=()
        )


def test_rejects_duplicate_source_record(
) -> None:
    first = _observation()

    duplicate = (
        WebIndicatorObservation(
            source=first.source,
            source_record_key=(
                first.source_record_key
            ),
            normalized_record_id=uuid4(),
            observed_at=(
                first.observed_at
            ),
            normalizer_version="1.0.0",
            labels=(
                "phishing",
            ),
        )
    )

    with pytest.raises(
        ValueError,
        match="unique by source record",
    ):
        _indicator(
            observations=(
                first,
                duplicate,
            )
        )


def test_rejects_update_before_creation(
) -> None:
    created_at = datetime(
        2026,
        8,
        5,
        10,
        0,
        tzinfo=UTC,
    )

    with pytest.raises(
        ValueError,
        match="updated_at",
    ):
        _indicator(
            created_at=created_at,
            updated_at=(
                created_at
                - timedelta(seconds=1)
            ),
        )


def test_rejects_naive_datetime(
) -> None:
    with pytest.raises(
        ValueError,
        match="timezone-aware",
    ):
        _indicator(
            created_at=datetime(
                2026,
                8,
                5,
            )
        )


def test_rejects_non_url_indicator_type(
) -> None:
    with pytest.raises(
        ValueError,
        match="indicator_type",
    ):
        indicator = _indicator()

        CanonicalWebIndicator(
            id=indicator.id,
            canonical_value=(
                indicator.canonical_value
            ),
            value_hash=(
                indicator.value_hash
            ),
            hostname=indicator.hostname,
            observations=(
                indicator.observations
            ),
            created_at=(
                indicator.created_at
            ),
            updated_at=(
                indicator.updated_at
            ),
            indicator_type="hostname",
        )