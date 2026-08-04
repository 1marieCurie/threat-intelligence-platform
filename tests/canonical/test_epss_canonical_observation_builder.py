from __future__ import annotations

from datetime import (
    UTC,
    date,
    datetime,
    timedelta,
    timezone,
)

import pytest

from application.models.epss_snapshot import (
    EPSSSnapshot,
)
from application.services.epss_canonical_observation_builder import (
    EPSSCanonicalObservationBuilder,
)


def _snapshot(
    *,
    score_date: date = date(
        2026,
        8,
        4,
    ),
) -> EPSSSnapshot:
    return EPSSSnapshot(
        score=0.42,
        percentile=0.87,
        score_date=score_date,
        api_version="v2025.03.14",
    )


def test_build_creates_provisional_cve_observation(
) -> None:
    synchronized_at = datetime(
        2026,
        8,
        4,
        12,
        30,
        tzinfo=UTC,
    )

    observation = (
        EPSSCanonicalObservationBuilder()
        .build(
            cve_id="CVE-2026-12345",
            snapshot=_snapshot(),
            synchronized_at=(
                synchronized_at
            ),
        )
    )

    assert (
        observation.suggested_status
        == "provisional"
    )

    assert len(
        observation.identifiers
    ) == 1

    identifier = (
        observation.identifiers[0]
    )

    assert identifier.namespace == "CVE"

    assert (
        identifier.value
        == "CVE-2026-12345"
    )

    assert identifier.is_primary is True

    evidence = observation.evidence

    assert evidence.source == "epss"

    assert evidence.source_record_key == (
        "CVE-2026-12345"
    )

    assert evidence.normalized_record_id == (
        "CVE-2026-12345"
    )

    assert (
        evidence.evidence_type
        == "epss_snapshot"
    )

    assert (
        evidence.correlation_rule
        == "exact_cve"
    )

    assert (
        evidence.observed_at
        == synchronized_at
    )

    assert (
        evidence.last_observed_at
        == synchronized_at
    )

    assert (
        evidence.source_published_at
        == datetime(
            2026,
            8,
            4,
            tzinfo=UTC,
        )
    )

    assert (
        evidence.correlation_confidence
        == 1.0
    )

    assert evidence.record_hash is None


def test_build_normalizes_cve_identifier(
) -> None:
    observation = (
        EPSSCanonicalObservationBuilder()
        .build(
            cve_id=(
                "  cve-2026-54321  "
            ),
            snapshot=_snapshot(),
            synchronized_at=datetime(
                2026,
                8,
                4,
                13,
                0,
                tzinfo=UTC,
            ),
        )
    )

    assert (
        observation.identifiers[0].value
        == "CVE-2026-54321"
    )

    assert (
        observation.evidence
        .source_record_key
        == "CVE-2026-54321"
    )


def test_build_converts_observation_time_to_utc(
) -> None:
    source_timezone = timezone(timedelta(hours=2))

    observation = (
        EPSSCanonicalObservationBuilder()
        .build(
            cve_id="CVE-2026-10001",
            snapshot=_snapshot(),
            synchronized_at=datetime(
                2026,
                8,
                4,
                14,
                0,
                tzinfo=source_timezone,
            ),
        )
    )

    assert (
        observation.evidence.observed_at
        == datetime(
            2026,
            8,
            4,
            12,
            0,
            tzinfo=UTC,
        )
    )


def test_build_keeps_stable_evidence_key_across_snapshots(
) -> None:
    builder = (
        EPSSCanonicalObservationBuilder()
    )

    first = builder.build(
        cve_id="CVE-2026-20001",
        snapshot=_snapshot(
            score_date=date(
                2026,
                8,
                3,
            )
        ),
        synchronized_at=datetime(
            2026,
            8,
            3,
            10,
            0,
            tzinfo=UTC,
        ),
    )

    second = builder.build(
        cve_id="CVE-2026-20001",
        snapshot=_snapshot(
            score_date=date(
                2026,
                8,
                4,
            )
        ),
        synchronized_at=datetime(
            2026,
            8,
            4,
            10,
            0,
            tzinfo=UTC,
        ),
    )

    assert (
        first.evidence.key
        == second.evidence.key
        == (
            "epss",
            "CVE-2026-20001",
        )
    )

    assert first.evidence.source_published_at is not None
    assert second.evidence.source_published_at is not None
    assert (
        first.evidence.source_published_at
        < second.evidence.source_published_at
    )


def test_build_rejects_invalid_snapshot(
) -> None:
    with pytest.raises(
        TypeError,
        match=(
            "snapshot must be "
            "an EPSSSnapshot"
        ),
    ):
        EPSSCanonicalObservationBuilder().build(
            cve_id="CVE-2026-30001",
            snapshot=object(),  # type: ignore[arg-type]
            synchronized_at=datetime.now(
                UTC
            ),
        )


def test_build_rejects_naive_synchronized_at(
) -> None:
    with pytest.raises(
        ValueError,
        match=(
            "synchronized_at must be "
            "timezone-aware"
        ),
    ):
        EPSSCanonicalObservationBuilder().build(
            cve_id="CVE-2026-30002",
            snapshot=_snapshot(),
            synchronized_at=datetime(
                2026,
                8,
                4,
                10,
                0,
            ),
        )


def test_build_rejects_invalid_cve(
) -> None:
    with pytest.raises(
        ValueError,
        match=(
            "value must be a valid "
            "CVE identifier"
        ),
    ):
        EPSSCanonicalObservationBuilder().build(
            cve_id="INVALID-2026-1234",
            snapshot=_snapshot(),
            synchronized_at=datetime.now(
                UTC
            ),
        )