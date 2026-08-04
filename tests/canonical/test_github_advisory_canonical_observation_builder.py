from __future__ import annotations

from datetime import (
    UTC,
    datetime,
    timedelta,
    timezone,
)
from uuid import uuid4

import pytest

from application.models.github_advisory_canonical_source_record import (
    GitHubAdvisoryCanonicalSourceRecord,
)
from application.services.github_advisory_canonical_observation_builder import (
    GitHubAdvisoryCanonicalObservationBuilder,
    GitHubAdvisoryCanonicalObservationError,
)


def _record(
    *,
    ghsa_id: str = (
        "GHSA-abcd-1234-efgh"
    ),
    cve_id: str | None = (
        "CVE-2026-12345"
    ),
    normalized_at: datetime | None = None,
    withdrawn_at: datetime | None = None,
) -> GitHubAdvisoryCanonicalSourceRecord:
    return GitHubAdvisoryCanonicalSourceRecord(
        normalized_record_id=uuid4(),
        ghsa_id=ghsa_id,
        cve_id=cve_id,
        published_at=datetime(
            2026,
            8,
            2,
            10,
            0,
            tzinfo=UTC,
        ),
        updated_at=datetime(
            2026,
            8,
            3,
            11,
            0,
            tzinfo=UTC,
        ),
        withdrawn_at=withdrawn_at,
        normalized_at=(
            normalized_at
            or datetime(
                2026,
                8,
                4,
                12,
                0,
                tzinfo=UTC,
            )
        ),
    )


def test_build_creates_cve_and_ghsa_observation(
) -> None:
    record = _record()

    observation = (
        GitHubAdvisoryCanonicalObservationBuilder()
        .build(
            record=record
        )
    )

    assert (
        observation.suggested_status
        == "provisional"
    )

    assert [
        (
            identifier.namespace,
            identifier.value,
            identifier.is_primary,
        )
        for identifier
        in observation.identifiers
    ] == [
        (
            "CVE",
            "CVE-2026-12345",
            True,
        ),
        (
            "GHSA",
            "GHSA-ABCD-1234-EFGH",
            False,
        ),
    ]

    evidence = observation.evidence

    assert (
        evidence.source
        == "github_advisory"
    )

    assert evidence.source_record_key == (
        "GHSA-ABCD-1234-EFGH"
    )

    assert evidence.normalized_record_id == (
        str(record.normalized_record_id)
    )

    assert evidence.evidence_type == (
        "github_security_advisory"
    )

    assert evidence.correlation_rule == (
        "exact_cve_ghsa"
    )

    assert (
        evidence.observed_at
        == record.normalized_at
    )

    assert (
        evidence.source_published_at
        == record.published_at
    )

    assert (
        evidence.source_modified_at
        == record.updated_at
    )


def test_build_creates_ghsa_only_observation(
) -> None:
    observation = (
        GitHubAdvisoryCanonicalObservationBuilder()
        .build(
            record=_record(
                cve_id=None
            )
        )
    )

    assert len(
        observation.identifiers
    ) == 1

    identifier = (
        observation.identifiers[0]
    )

    assert identifier.namespace == "GHSA"

    assert (
        identifier.value
        == "GHSA-ABCD-1234-EFGH"
    )

    assert identifier.is_primary is True

    assert (
        observation.evidence
        .correlation_rule
        == "exact_ghsa"
    )


def test_record_normalizes_identifiers(
) -> None:
    record = _record(
        ghsa_id=(
            "  ghsa-abcd-1234-efgh  "
        ),
        cve_id=(
            "  cve-2026-54321  "
        ),
    )

    assert (
        record.ghsa_id
        == "GHSA-ABCD-1234-EFGH"
    )

    assert (
        record.cve_id
        == "CVE-2026-54321"
    )


def test_record_normalizes_dates_to_utc(
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


def test_build_keeps_stable_evidence_key(
) -> None:
    first = (
        GitHubAdvisoryCanonicalObservationBuilder()
        .build(
            record=_record()
        )
    )

    second = (
        GitHubAdvisoryCanonicalObservationBuilder()
        .build(
            record=_record()
        )
    )

    assert (
        first.evidence.key
        == second.evidence.key
        == (
            "github_advisory",
            "GHSA-ABCD-1234-EFGH",
        )
    )

    assert (
        first.evidence.normalized_record_id
        != second.evidence.normalized_record_id
    )


def test_build_rejects_withdrawn_advisory(
) -> None:
    withdrawn_at = datetime(
        2026,
        8,
        4,
        10,
        0,
        tzinfo=UTC,
    )

    with pytest.raises(
        GitHubAdvisoryCanonicalObservationError,
        match=(
            "Withdrawn GitHub advisories "
            "cannot produce"
        ),
    ):
        (
            GitHubAdvisoryCanonicalObservationBuilder()
            .build(
                record=_record(
                    withdrawn_at=(
                        withdrawn_at
                    )
                )
            )
        )


def test_build_rejects_invalid_record_type(
) -> None:
    with pytest.raises(
        TypeError,
        match=(
            "record must be a "
            "GitHubAdvisoryCanonicalSourceRecord"
        ),
    ):
        (
            GitHubAdvisoryCanonicalObservationBuilder()
            .build(
                record=object(),  # type: ignore[arg-type]
            )
        )


def test_record_rejects_invalid_ghsa(
) -> None:
    with pytest.raises(
        ValueError,
        match=(
            "value must be a valid "
            "GHSA identifier"
        ),
    ):
        _record(
            ghsa_id="INVALID-GHSA"
        )


def test_record_rejects_invalid_cve(
) -> None:
    with pytest.raises(
        ValueError,
        match=(
            "value must be a valid "
            "CVE identifier"
        ),
    ):
        _record(
            cve_id="INVALID-CVE"
        )


def test_record_rejects_naive_normalized_at(
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