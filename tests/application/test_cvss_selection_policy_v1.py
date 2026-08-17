from datetime import (
    datetime,
    timedelta,
    timezone,
)

import pytest

from application.services.cvss_selection_policy_v1 import (
    CvssObservation,
    CvssSelectionPolicyV1,
)


NOW = datetime(
    2026,
    8,
    17,
    15,
    0,
    tzinfo=timezone.utc,
)


def _observation(
    *,
    source_name: str = "github_advisory",
    source_role: str | None = None,
    version: str = "3.1",
    score: float = 7.5,
    vector: str | None = None,
    published_at: datetime | None = NOW,
    modified_at: datetime | None = NOW,
) -> CvssObservation:
    return CvssObservation(
        source_name=source_name,
        source_role=source_role,
        version=version,
        base_score=score,
        vector=vector,
        published_at=published_at,
        modified_at=modified_at,
    )


def test_empty_observations_return_none(
) -> None:
    policy = CvssSelectionPolicyV1()

    assert policy.select([]) is None


def test_cvss_4_beats_3_1(
) -> None:
    policy = CvssSelectionPolicyV1()

    selected = policy.select(
        [
            _observation(
                version="3.1",
                score=10.0,
            ),
            _observation(
                version="4.0",
                score=5.0,
            ),
        ]
    )

    assert selected is not None
    assert selected.version == "4.0"
    assert selected.base_score == 5.0


def test_cvss_3_1_beats_3_0(
) -> None:
    policy = CvssSelectionPolicyV1()

    selected = policy.select(
        [
            _observation(
                version="3.0",
                score=10.0,
            ),
            _observation(
                version="3.1",
                score=4.0,
            ),
        ]
    )

    assert selected is not None
    assert selected.version == "3.1"


def test_cvss_3_0_beats_unspecified_v3(
) -> None:
    policy = CvssSelectionPolicyV1()

    selected = policy.select(
        [
            _observation(
                version="3",
                score=9.9,
            ),
            _observation(
                version="3.0",
                score=5.0,
            ),
        ]
    )

    assert selected is not None
    assert selected.version == "3.0"


def test_unspecified_v3_is_kept_when_only_v3_exists(
) -> None:
    policy = CvssSelectionPolicyV1()

    selected = policy.select(
        [
            _observation(
                version="3",
                score=7.5,
            ),
        ]
    )

    assert selected is not None
    assert selected.version == "3.x"
    assert selected.base_score == 7.5


def test_cvss_3_beats_cvss_2(
) -> None:
    policy = CvssSelectionPolicyV1()

    selected = policy.select(
        [
            _observation(
                version="2.0",
                score=10.0,
            ),
            _observation(
                version="3",
                score=4.0,
            ),
        ]
    )

    assert selected is not None
    assert selected.version == "3.x"


def test_version_priority_does_not_choose_highest_score(
) -> None:
    policy = CvssSelectionPolicyV1()

    selected = policy.select(
        [
            _observation(
                version="3.1",
                score=2.0,
            ),
            _observation(
                version="3.0",
                score=10.0,
            ),
        ]
    )

    assert selected is not None

    assert selected.version == "3.1"
    assert selected.base_score == 2.0


def test_vendor_beats_cna_within_same_version(
) -> None:
    policy = CvssSelectionPolicyV1()

    selected = policy.select(
        [
            _observation(
                source_name="example-cna",
                source_role="CNA",
                version="3.1",
                modified_at=(
                    NOW
                    + timedelta(
                        days=10
                    )
                ),
            ),
            _observation(
                source_name="vendor",
                source_role="VENDOR",
                version="3.1",
                modified_at=NOW,
            ),
        ]
    )

    assert selected is not None
    assert selected.source_role == "VENDOR"


def test_authoritative_source_beats_newer_third_party(
) -> None:
    policy = CvssSelectionPolicyV1()

    selected = policy.select(
        [
            _observation(
                source_name="vendor",
                source_role="VENDOR",
                modified_at=NOW,
            ),
            _observation(
                source_name="other",
                source_role="THIRD_PARTY",
                modified_at=(
                    NOW
                    + timedelta(
                        days=30
                    )
                ),
            ),
        ]
    )

    assert selected is not None
    assert selected.source_role == "VENDOR"


def test_freshest_wins_inside_same_authority(
) -> None:
    policy = CvssSelectionPolicyV1()

    selected = policy.select(
        [
            _observation(
                source_name="older",
                source_role="NVD",
                modified_at=NOW,
            ),
            _observation(
                source_name="newer",
                source_role="NVD",
                modified_at=(
                    NOW
                    + timedelta(
                        hours=1
                    )
                ),
            ),
        ]
    )

    assert selected is not None
    assert selected.source_name == "newer"


def test_modified_at_has_priority_over_published_at_for_freshness(
) -> None:
    policy = CvssSelectionPolicyV1()

    selected = policy.select(
        [
            _observation(
                source_name="first",
                source_role="NVD",
                published_at=(
                    NOW
                    + timedelta(
                        days=50
                    )
                ),
                modified_at=NOW,
            ),
            _observation(
                source_name="second",
                source_role="NVD",
                published_at=NOW,
                modified_at=(
                    NOW
                    + timedelta(
                        days=1
                    )
                ),
            ),
        ]
    )

    assert selected is not None
    assert selected.source_name == "second"


def test_zero_score_is_valid(
) -> None:
    observation = _observation(
        score=0.0
    )

    assert observation.base_score == 0.0


def test_score_above_10_is_rejected(
) -> None:
    with pytest.raises(
        ValueError,
        match="between 0 and 10",
    ):
        _observation(
            score=10.1
        )


def test_naive_datetime_is_rejected(
) -> None:
    with pytest.raises(
        ValueError,
        match="timezone-aware",
    ):
        _observation(
            modified_at=datetime(
                2026,
                8,
                17,
                15,
                0,
            )
        )