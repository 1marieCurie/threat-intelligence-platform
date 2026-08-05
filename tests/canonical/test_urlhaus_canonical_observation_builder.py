from __future__ import annotations

from datetime import (
    UTC,
    datetime,
    timedelta,
)
from uuid import uuid4

import pytest

from application.models.urlhaus_canonical_source_record import (
    URLhausCanonicalSourceRecord,
)
from application.services.urlhaus_canonical_observation_builder import (
    URLhausCanonicalObservationBuilder,
)


def _record(
    *,
    malicious_url: str = (
        "HTTP://Example.COM:80/payload"
    ),
    url_status: str | None = "online",
) -> URLhausCanonicalSourceRecord:
    normalized_at = datetime(
        2026,
        8,
        5,
        18,
        0,
        tzinfo=UTC,
    )

    return URLhausCanonicalSourceRecord(
        normalized_record_id=uuid4(),
        urlhaus_id=98765,
        malicious_url=malicious_url,
        normalized_at=normalized_at,
        normalizer_version="1.0.0",
        date_added=(
            normalized_at
            - timedelta(days=1)
        ),
        url_status=url_status,
    )


def test_builds_online_urlhaus_observation(
) -> None:
    record = _record()

    result = (
        URLhausCanonicalObservationBuilder()
        .build(
            record=record
        )
    )

    assert result.identity.canonical_value == (
        "http://example.com/payload"
    )

    assert result.observation.source == (
        "urlhaus"
    )

    assert (
        result.observation.source_record_key
        == "98765"
    )

    assert (
        result.observation.normalized_record_id
        == record.normalized_record_id
    )

    assert result.observation.source_status == (
        "online"
    )

    assert result.observation.is_active is True

    assert result.observation.labels == (
        "malware_distribution",
    )

    assert result.observation.observed_at == (
        record.date_added
    )

    assert (
        result.observation.last_observed_at
        == record.normalized_at
    )


def test_builds_offline_urlhaus_observation(
) -> None:
    result = (
        URLhausCanonicalObservationBuilder()
        .build(
            record=_record(
                url_status="offline"
            )
        )
    )

    assert result.observation.source_status == (
        "offline"
    )

    assert result.observation.is_active is False


def test_ignores_unknown_provider_status(
) -> None:
    result = (
        URLhausCanonicalObservationBuilder()
        .build(
            record=_record(
                url_status="unknown_status"
            )
        )
    )

    assert (
        result.observation.source_status
        is None
    )

    assert result.observation.is_active is None


def test_rejects_invalid_record_type(
) -> None:
    with pytest.raises(
        TypeError,
        match="URLhausCanonicalSourceRecord",
    ):
        (
            URLhausCanonicalObservationBuilder()
            .build(
                record=object(),  # type: ignore[arg-type]
            )
        )


def test_rejects_naive_normalization_datetime(
) -> None:
    with pytest.raises(
        ValueError,
        match="timezone-aware",
    ):
        URLhausCanonicalSourceRecord(
            normalized_record_id=uuid4(),
            urlhaus_id=98765,
            malicious_url=(
                "https://example.com/file"
            ),
            normalized_at=datetime(
                2026,
                8,
                5,
            ),
            normalizer_version="1.0.0",
        )