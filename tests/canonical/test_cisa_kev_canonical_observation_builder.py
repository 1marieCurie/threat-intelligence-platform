from __future__ import annotations

from datetime import (
    UTC,
    date,
    datetime,
    timedelta,
    timezone,
)
from uuid import uuid4

import pytest

from application.models.cisa_kev_canonical_source_record import (
    CisaKevCanonicalSourceRecord,
)
from application.services.cisa_kev_canonical_observation_builder import (
    CisaKevCanonicalObservationBuilder,
)


def _record(
    *,
    cve_id: str = "CVE-2026-12345",
    normalized_at: datetime | None = None,
) -> CisaKevCanonicalSourceRecord:
    return CisaKevCanonicalSourceRecord(
        normalized_record_id=uuid4(),
        cve_id=cve_id,
        date_added=date(
            2026,
            8,
            4,
        ),
        normalized_at=(
            normalized_at
            or datetime(
                2026,
                8,
                4,
                12,
                30,
                tzinfo=UTC,
            )
        ),
    )


def test_build_creates_active_cve_observation(
) -> None:
    record = _record()

    observation = (
        CisaKevCanonicalObservationBuilder()
        .build(
            record=record
        )
    )

    assert (
        observation.suggested_status
        == "active"
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

    assert evidence.source == "cisa_kev"

    assert evidence.source_record_key == (
        "CVE-2026-12345"
    )

    assert evidence.normalized_record_id == (
        str(record.normalized_record_id)
    )

    assert evidence.evidence_type == (
        "known_exploited_vulnerability"
    )

    assert (
        evidence.correlation_rule
        == "exact_cve"
    )

    assert (
        evidence.observed_at
        == record.normalized_at
    )

    assert (
        evidence.last_observed_at
        == record.normalized_at
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


def test_source_record_normalizes_cve(
) -> None:
    record = _record(
        cve_id=(
            "  cve-2026-54321  "
        )
    )

    assert (
        record.cve_id
        == "CVE-2026-54321"
    )

    observation = (
        CisaKevCanonicalObservationBuilder()
        .build(
            record=record
        )
    )

    assert (
        observation.evidence
        .source_record_key
        == "CVE-2026-54321"
    )


def test_source_record_normalizes_time_to_utc(
) -> None:
    source_timezone = timezone(
        timedelta(
            hours=2
        )
    )

    record = _record(
        normalized_at=datetime(
            2026,
            8,
            4,
            14,
            0,
            tzinfo=source_timezone,
        )
    )

    assert (
        record.normalized_at
        == datetime(
            2026,
            8,
            4,
            12,
            0,
            tzinfo=UTC,
        )
    )


def test_build_keeps_stable_evidence_key_across_records(
) -> None:
    first = (
        CisaKevCanonicalObservationBuilder()
        .build(
            record=_record()
        )
    )

    second = (
        CisaKevCanonicalObservationBuilder()
        .build(
            record=_record()
        )
    )

    assert (
        first.evidence.key
        == second.evidence.key
        == (
            "cisa_kev",
            "CVE-2026-12345",
        )
    )

    assert (
        first.evidence.normalized_record_id
        != second.evidence.normalized_record_id
    )


def test_build_rejects_invalid_record_type(
) -> None:
    with pytest.raises(
        TypeError,
        match=(
            "record must be a "
            "CisaKevCanonicalSourceRecord"
        ),
    ):
        CisaKevCanonicalObservationBuilder().build(
            record=object(),  # type: ignore[arg-type]
        )


def test_source_record_rejects_invalid_cve(
) -> None:
    with pytest.raises(
        ValueError,
        match=(
            "value must be a valid "
            "CVE identifier"
        ),
    ):
        _record(
            cve_id="INVALID-2026-1234"
        )


def test_source_record_rejects_naive_normalized_at(
) -> None:
    with pytest.raises(
        ValueError,
        match=(
            "normalized_at must be "
            "timezone-aware"
        ),
    ):
        _record(
            normalized_at=datetime(
                2026,
                8,
                4,
                12,
                0,
            )
        )


def test_source_record_rejects_datetime_as_date_added(
) -> None:
    with pytest.raises(
        TypeError,
        match="date_added must be a date",
    ):
        CisaKevCanonicalSourceRecord(
            normalized_record_id=uuid4(),
            cve_id="CVE-2026-12345",
            date_added=datetime(
                2026,
                8,
                4,
                tzinfo=UTC,
            ),  # type: ignore[arg-type]
            normalized_at=datetime.now(
                UTC
            ),
        )