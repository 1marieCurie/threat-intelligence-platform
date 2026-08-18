from __future__ import annotations

from uuid import uuid4

import pytest

from application.services.alert_evaluation_policy_v1 import (
    AlertEvaluationPolicyV1,
)


def _evaluate(
    *,
    applicability_status: str = "confirmed",
    is_new_exposure: bool = False,
    previous_priority: str | None = "HIGH",
    current_priority: str = "HIGH",
    previous_is_kev: bool | None = False,
    current_is_kev: bool = False,
):
    policy = (
        AlertEvaluationPolicyV1()
    )

    return policy.evaluate(
        exposure_id=uuid4(),
        applicability_status=(
            applicability_status
        ),
        is_new_exposure=(
            is_new_exposure
        ),
        previous_priority=(
            previous_priority
        ),
        current_priority=(
            current_priority
        ),
        previous_is_kev=(
            previous_is_kev
        ),
        current_is_kev=(
            current_is_kev
        ),
    )


def test_new_confirmed_critical_exposure_alerts(
) -> None:
    candidates = _evaluate(
        is_new_exposure=True,
        previous_priority=None,
        current_priority="CRITICAL",
        previous_is_kev=None,
    )

    assert [
        candidate.alert_type
        for candidate in candidates
    ] == [
        "new_confirmed_critical_exposure"
    ]


def test_new_confirmed_high_does_not_alert(
) -> None:
    assert (
        _evaluate(
            is_new_exposure=True,
            previous_priority=None,
            current_priority="HIGH",
            previous_is_kev=None,
        )
        == ()
    )


def test_confirmed_entering_kev_alerts(
) -> None:
    candidates = _evaluate(
        previous_priority="HIGH",
        current_priority="HIGH",
        previous_is_kev=False,
        current_is_kev=True,
    )

    assert [
        candidate.alert_type
        for candidate in candidates
    ] == [
        "confirmed_exposure_entered_kev"
    ]


def test_new_exposure_already_kev_does_not_emit_entered_kev(
) -> None:
    candidates = _evaluate(
        is_new_exposure=True,
        previous_priority=None,
        current_priority="HIGH",
        previous_is_kev=None,
        current_is_kev=True,
    )

    assert candidates == ()


@pytest.mark.parametrize(
    "previous_priority",
    [
        "LOW",
        "MEDIUM",
        "HIGH",
    ],
)
def test_transition_to_critical_alerts(
    previous_priority: str,
) -> None:
    candidates = _evaluate(
        previous_priority=(
            previous_priority
        ),
        current_priority="CRITICAL",
    )

    assert [
        candidate.alert_type
        for candidate in candidates
    ] == [
        "priority_transition_to_critical"
    ]


def test_medium_to_high_does_not_alert(
) -> None:
    assert (
        _evaluate(
            previous_priority="MEDIUM",
            current_priority="HIGH",
        )
        == ()
    )


def test_high_to_high_does_not_alert(
) -> None:
    assert (
        _evaluate(
            previous_priority="HIGH",
            current_priority="HIGH",
        )
        == ()
    )


def test_critical_to_critical_does_not_alert(
) -> None:
    assert (
        _evaluate(
            previous_priority="CRITICAL",
            current_priority="CRITICAL",
        )
        == ()
    )


@pytest.mark.parametrize(
    (
        "previous_priority",
        "current_priority",
        "previous_is_kev",
        "current_is_kev",
        "is_new",
    ),
    [
        (
            None,
            "CRITICAL",
            None,
            False,
            True,
        ),
        (
            "HIGH",
            "CRITICAL",
            False,
            False,
            False,
        ),
        (
            "HIGH",
            "CRITICAL",
            False,
            True,
            False,
        ),
    ],
)
def test_potential_exposure_never_emits_v1_critical_alert(
    previous_priority: str | None,
    current_priority: str,
    previous_is_kev: bool | None,
    current_is_kev: bool,
    is_new: bool,
) -> None:
    assert (
        _evaluate(
            applicability_status="potential",
            is_new_exposure=is_new,
            previous_priority=(
                previous_priority
            ),
            current_priority=(
                current_priority
            ),
            previous_is_kev=(
                previous_is_kev
            ),
            current_is_kev=(
                current_is_kev
            ),
        )
        == ()
    )


def test_kev_and_priority_transition_can_create_two_distinct_alerts(
) -> None:
    candidates = _evaluate(
        previous_priority="HIGH",
        current_priority="CRITICAL",
        previous_is_kev=False,
        current_is_kev=True,
    )

    assert {
        candidate.alert_type
        for candidate in candidates
    } == {
        "confirmed_exposure_entered_kev",
        "priority_transition_to_critical",
    }


def test_deduplication_key_is_deterministic(
) -> None:
    exposure_id = uuid4()

    policy = (
        AlertEvaluationPolicyV1()
    )

    first = policy.evaluate(
        exposure_id=exposure_id,
        applicability_status="confirmed",
        is_new_exposure=True,
        previous_priority=None,
        current_priority="CRITICAL",
        previous_is_kev=None,
        current_is_kev=False,
    )

    second = policy.evaluate(
        exposure_id=exposure_id,
        applicability_status="confirmed",
        is_new_exposure=True,
        previous_priority=None,
        current_priority="CRITICAL",
        previous_is_kev=None,
        current_is_kev=False,
    )

    assert (
        first[0].deduplication_key
        == second[0].deduplication_key
    )

    assert (
        first[0].deduplication_key
        == (
            "alert/v1:"
            "new_confirmed_critical_exposure:"
            f"{exposure_id}"
        )
    )


def test_different_alert_types_have_different_deduplication_keys(
) -> None:
    exposure_id = uuid4()

    policy = (
        AlertEvaluationPolicyV1()
    )

    candidates = policy.evaluate(
        exposure_id=exposure_id,
        applicability_status="confirmed",
        is_new_exposure=False,
        previous_priority="HIGH",
        current_priority="CRITICAL",
        previous_is_kev=False,
        current_is_kev=True,
    )

    assert len(
        candidates
    ) == 2

    assert (
        candidates[0].deduplication_key
        != candidates[1].deduplication_key
    )


def test_policy_version_is_stable(
) -> None:
    assert (
        AlertEvaluationPolicyV1
        .POLICY_VERSION
        == "1.0.0"
    )