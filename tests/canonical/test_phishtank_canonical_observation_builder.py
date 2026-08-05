from __future__ import annotations

from datetime import (
    UTC,
    datetime,
    timedelta,
)
from uuid import uuid4

import pytest

from application.models.phishtank_canonical_source_record import (
    PhishTankCanonicalSourceRecord,
)
from application.services.phishtank_canonical_observation_builder import (
    PhishTankCanonicalObservationBuilder,
)


def _record(
    *,
    phishing_url: str = (
        "HTTPS://Example.COM.:443/login"
    ),
    verified: bool | None = True,
    online: bool | None = True,
    submission_time: datetime | None = None,
    verification_time: datetime | None = None,
) -> PhishTankCanonicalSourceRecord:
    normalized_at = datetime(
        2026,
        8,
        5,
        18,
        0,
        tzinfo=UTC,
    )

    return PhishTankCanonicalSourceRecord(
        normalized_record_id=uuid4(),
        phish_id=12345,
        phishing_url=phishing_url,
        normalized_at=normalized_at,
        normalizer_version="1.0.1",
        submission_time=(
            submission_time
            or normalized_at
            - timedelta(hours=2)
        ),
        verification_time=(
            verification_time
            or normalized_at
            - timedelta(hours=1)
        ),
        verified=verified,
        online=online,
    )


def test_builds_verified_phishtank_observation(
) -> None:
    record = _record()

    result = (
        PhishTankCanonicalObservationBuilder()
        .build(
            record=record
        )
    )

    assert result.identity.canonical_value == (
        "https://example.com/login"
    )

    assert result.observation.source == (
        "phishtank"
    )

    assert (
        result.observation.source_record_key
        == "12345"
    )

    assert (
        result.observation.normalized_record_id
        == record.normalized_record_id
    )

    assert result.observation.source_status == (
        "verified"
    )

    assert result.observation.is_active is True

    assert result.observation.labels == (
        "phishing",
    )

    assert result.observation.observed_at == (
        record.submission_time
    )

    assert (
        result.observation.last_observed_at
        == record.normalized_at
    )


def test_marks_unverified_record_as_suspected(
) -> None:
    result = (
        PhishTankCanonicalObservationBuilder()
        .build(
            record=_record(
                verified=False,
                online=False,
            )
        )
    )

    assert result.observation.source_status == (
        "unverified"
    )

    assert result.observation.is_active is False

    assert result.observation.labels == (
        "suspected_phishing",
    )


def test_uses_normalized_time_without_source_dates(
) -> None:
    normalized_at = datetime(
        2026,
        8,
        5,
        18,
        0,
        tzinfo=UTC,
    )

    record = PhishTankCanonicalSourceRecord(
        normalized_record_id=uuid4(),
        phish_id=777,
        phishing_url=(
            "https://example.com/path"
        ),
        normalized_at=normalized_at,
        normalizer_version="1.0.1",
    )

    result = (
        PhishTankCanonicalObservationBuilder()
        .build(
            record=record
        )
    )

    assert result.observation.observed_at == (
        normalized_at
    )

    assert (
        result.observation.last_observed_at
        == normalized_at
    )


def test_rejects_invalid_record_type(
) -> None:
    with pytest.raises(
        TypeError,
        match="PhishTankCanonicalSourceRecord",
    ):
        (
            PhishTankCanonicalObservationBuilder()
            .build(
                record=object(),  # type: ignore[arg-type]
            )
        )


def test_rejects_invalid_source_time_order(
) -> None:
    submission_time = datetime(
        2026,
        8,
        5,
        12,
        0,
        tzinfo=UTC,
    )

    with pytest.raises(
        ValueError,
        match="verification_time",
    ):
        _record(
            submission_time=submission_time,
            verification_time=(
                submission_time
                - timedelta(seconds=1)
            ),
        )