from __future__ import annotations

from datetime import (
    UTC,
    date,
    datetime,
)
from uuid import (
    UUID,
    uuid4,
)

import pytest

from application.models.cisa_kev_canonical_source_record import (
    CisaKevCanonicalSourceRecord,
)
from application.models.github_advisory_canonical_source_record import (
    GitHubAdvisoryCanonicalSourceRecord,
)
from application.services.canonical_cwe_association_builder import (
    CanonicalCWEAssociationBuilder,
)


_NORMALIZED_RECORD_ID = UUID(
    "00000000-0000-0000-0000-000000000001"
)

_OBSERVED_AT = datetime(
    2026,
    8,
    5,
    10,
    0,
    tzinfo=UTC,
)

_MODIFIED_AT = datetime(
    2026,
    8,
    5,
    11,
    0,
    tzinfo=UTC,
)


def _github_record(
    *,
    cwe_ids: tuple[str, ...] = (
        "CWE-79",
        "CWE-89",
    ),
) -> GitHubAdvisoryCanonicalSourceRecord:
    return GitHubAdvisoryCanonicalSourceRecord(
        normalized_record_id=(
            _NORMALIZED_RECORD_ID
        ),
        ghsa_id="GHSA-AAAA-BBBB-CCCC",
        cve_id="CVE-2026-12345",
        cwe_ids=cwe_ids,
        normalized_at=_OBSERVED_AT,
        updated_at=_MODIFIED_AT,
    )


def _cisa_record(
    *,
    cwe_ids: tuple[str, ...] = (
        "CWE-79",
        "CWE-89",
    ),
) -> CisaKevCanonicalSourceRecord:
    return CisaKevCanonicalSourceRecord(
        normalized_record_id=(
            _NORMALIZED_RECORD_ID
        ),
        cve_id="CVE-2026-12345",
        cwe_ids=cwe_ids,
        date_added=date(
            2026,
            8,
            4,
        ),
        normalized_at=_OBSERVED_AT,
    )


def test_builds_github_associations(
) -> None:
    vulnerability_id = uuid4()

    associations = (
        CanonicalCWEAssociationBuilder()
        .build_for_github_advisory(
            record=_github_record(),
            vulnerability_id=(
                vulnerability_id
            ),
            official_cwe_ids=(
                "CWE-79",
                "CWE-89",
            ),
        )
    )

    assert len(associations) == 2

    first = associations[0]
    second = associations[1]

    assert (
        first.vulnerability_id
        == vulnerability_id
    )

    assert first.cwe_id == "CWE-79"
    assert second.cwe_id == "CWE-89"

    assert (
        first.source
        == "github_advisory"
    )

    assert (
        first.source_record_key
        == "GHSA-AAAA-BBBB-CCCC"
    )

    assert (
        first.normalized_record_id
        == str(_NORMALIZED_RECORD_ID)
    )

    assert (
        first.observed_at
        == _OBSERVED_AT
    )

    assert (
        first.last_observed_at
        == _OBSERVED_AT
    )

    assert (
        first.source_modified_at
        == _MODIFIED_AT
    )


def test_builds_cisa_kev_associations(
) -> None:
    vulnerability_id = uuid4()

    associations = (
        CanonicalCWEAssociationBuilder()
        .build_for_cisa_kev(
            record=_cisa_record(),
            vulnerability_id=(
                vulnerability_id
            ),
            official_cwe_ids=(
                "CWE-79",
                "CWE-89",
            ),
        )
    )

    assert len(associations) == 2

    first = associations[0]

    assert (
        first.vulnerability_id
        == vulnerability_id
    )

    assert first.cwe_id == "CWE-79"

    assert first.source == "cisa_kev"

    assert (
        first.source_record_key
        == "CVE-2026-12345"
    )

    assert (
        first.normalized_record_id
        == str(_NORMALIZED_RECORD_ID)
    )

    assert (
        first.observed_at
        == _OBSERVED_AT
    )

    assert (
        first.last_observed_at
        == _OBSERVED_AT
    )

    assert (
        first.source_modified_at
        is None
    )


def test_keeps_only_catalogued_source_cwe_ids(
) -> None:
    associations = (
        CanonicalCWEAssociationBuilder()
        .build_for_github_advisory(
            record=_github_record(
                cwe_ids=(
                    "CWE-79",
                    "CWE-89",
                    "CWE-94",
                )
            ),
            vulnerability_id=uuid4(),
            official_cwe_ids=(
                "CWE-79",
                "CWE-94",
                "CWE-200",
            ),
        )
    )

    assert tuple(
        association.cwe_id
        for association in associations
    ) == (
        "CWE-79",
        "CWE-94",
    )


def test_returns_empty_when_record_has_no_cwe(
) -> None:
    associations = (
        CanonicalCWEAssociationBuilder()
        .build_for_cisa_kev(
            record=_cisa_record(
                cwe_ids=()
            ),
            vulnerability_id=uuid4(),
            official_cwe_ids=(
                "CWE-79",
            ),
        )
    )

    assert associations == ()


def test_returns_empty_when_no_source_cwe_is_catalogued(
) -> None:
    associations = (
        CanonicalCWEAssociationBuilder()
        .build_for_github_advisory(
            record=_github_record(),
            vulnerability_id=uuid4(),
            official_cwe_ids=(
                "CWE-94",
            ),
        )
    )

    assert associations == ()


def test_preserves_source_cwe_order(
) -> None:
    associations = (
        CanonicalCWEAssociationBuilder()
        .build_for_github_advisory(
            record=_github_record(
                cwe_ids=(
                    "CWE-94",
                    "CWE-79",
                    "CWE-89",
                )
            ),
            vulnerability_id=uuid4(),
            official_cwe_ids=(
                "CWE-79",
                "CWE-89",
                "CWE-94",
            ),
        )
    )

    assert tuple(
        association.cwe_id
        for association in associations
    ) == (
        "CWE-94",
        "CWE-79",
        "CWE-89",
    )


def test_rejects_invalid_github_record_type(
) -> None:
    with pytest.raises(
        TypeError,
        match=(
            "record must be a "
            "GitHubAdvisoryCanonicalSourceRecord"
        ),
    ):
        (
            CanonicalCWEAssociationBuilder()
            .build_for_github_advisory(
                record=object(),  # type: ignore[arg-type]
                vulnerability_id=uuid4(),
                official_cwe_ids=(),
            )
        )


def test_rejects_invalid_cisa_record_type(
) -> None:
    with pytest.raises(
        TypeError,
        match=(
            "record must be a "
            "CisaKevCanonicalSourceRecord"
        ),
    ):
        (
            CanonicalCWEAssociationBuilder()
            .build_for_cisa_kev(
                record=object(),  # type: ignore[arg-type]
                vulnerability_id=uuid4(),
                official_cwe_ids=(),
            )
        )


def test_rejects_non_uuid_vulnerability_id(
) -> None:
    with pytest.raises(
        TypeError,
        match=(
            "vulnerability_id must be a UUID"
        ),
    ):
        (
            CanonicalCWEAssociationBuilder()
            .build_for_github_advisory(
                record=_github_record(),
                vulnerability_id=(
                    "invalid"  # type: ignore[arg-type]
                ),
                official_cwe_ids=(),
            )
        )


def test_rejects_nil_vulnerability_id(
) -> None:
    with pytest.raises(
        ValueError,
        match=(
            "vulnerability_id must not be nil"
        ),
    ):
        (
            CanonicalCWEAssociationBuilder()
            .build_for_cisa_kev(
                record=_cisa_record(),
                vulnerability_id=UUID(
                    int=0
                ),
                official_cwe_ids=(),
            )
        )


def test_rejects_single_official_cwe_string(
) -> None:
    with pytest.raises(
        TypeError,
        match=(
            "official_cwe_ids must be an "
            "iterable of canonical identifiers"
        ),
    ):
        (
            CanonicalCWEAssociationBuilder()
            .build_for_github_advisory(
                record=_github_record(),
                vulnerability_id=uuid4(),
                official_cwe_ids=(
                    "CWE-79"
                ),  # type: ignore[arg-type]
            )
        )


@pytest.mark.parametrize(
    "official_cwe_id",
    [
        "cwe-79",
        "79",
        "CWE-079",
    ],
)
def test_rejects_non_canonical_official_cwe_id(
    official_cwe_id: str,
) -> None:
    with pytest.raises(
        ValueError,
        match=(
            "must already be canonical"
        ),
    ):
        (
            CanonicalCWEAssociationBuilder()
            .build_for_github_advisory(
                record=_github_record(),
                vulnerability_id=uuid4(),
                official_cwe_ids=(
                    official_cwe_id,
                ),
            )
        )


@pytest.mark.parametrize(
    "official_cwe_id",
    [
        "",
        "invalid",
        "CWE-0",
        "CWE-A",
    ],
)
def test_rejects_invalid_official_cwe_id(
    official_cwe_id: str,
) -> None:
    with pytest.raises(
        ValueError,
        match=(
            "official CWE identifier "
            "must be valid"
        ),
    ):
        (
            CanonicalCWEAssociationBuilder()
            .build_for_cisa_kev(
                record=_cisa_record(),
                vulnerability_id=uuid4(),
                official_cwe_ids=(
                    official_cwe_id,
                ),
            )
        )


def test_deduplicates_official_cwe_ids(
) -> None:
    associations = (
        CanonicalCWEAssociationBuilder()
        .build_for_github_advisory(
            record=_github_record(),
            vulnerability_id=uuid4(),
            official_cwe_ids=(
                "CWE-79",
                "CWE-79",
                "CWE-89",
            ),
        )
    )

    assert tuple(
        association.cwe_id
        for association in associations
    ) == (
        "CWE-79",
        "CWE-89",
    )