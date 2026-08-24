from __future__ import annotations

from datetime import (
    UTC,
    datetime,
)

from application.services.reevaluate_threat_intelligence_targets_service import (
    ReevaluateThreatIntelligenceTargetsResult,
)
from application.services.threat_intelligence_scheduler_cycle_service import (
    STAGE_STATUS_COMPLETED,
    STAGE_STATUS_FAILED,
    ThreatIntelligenceRefreshStageResult,
    ThreatIntelligenceSchedulerCycleService,
)


EVALUATED_AT = datetime(
    2026,
    8,
    24,
    15,
    0,
    tzinfo=UTC,
)


class FakeStage:
    def __init__(
        self,
        *,
        name: str,
        calls: list[str],
        changed: bool,
        processed_count: int,
    ) -> None:
        self.name = name
        self.calls = calls
        self.changed = changed
        self.processed_count = (
            processed_count
        )

    def run(
        self,
    ):
        self.calls.append(
            self.name
        )

        return (
            ThreatIntelligenceRefreshStageResult(
                changed=self.changed,
                processed_count=(
                    self.processed_count
                ),
            )
        )


class FailingStage:
    def __init__(
        self,
        *,
        name: str,
        calls: list[str],
        message: str = "stage failure",
    ) -> None:
        self.name = name
        self.calls = calls
        self.message = message

    def run(
        self,
    ):
        self.calls.append(
            self.name
        )

        raise RuntimeError(
            self.message
        )


class InvalidStage:
    def __init__(
        self,
        *,
        calls: list[str],
        name: str,
    ) -> None:
        self.calls = calls
        self.name = name

    def run(
        self,
    ):
        self.calls.append(
            self.name
        )

        return object()


class FakeReevaluator:
    def __init__(
        self,
        *,
        calls: list[str],
        should_fail: bool = False,
    ) -> None:
        self.calls = calls

        self.arguments = []

        self.should_fail = (
            should_fail
        )

    def reevaluate(
        self,
        *,
        cisa_kev_changed,
        github_advisory_changed,
        epss_changed,
        evaluated_at,
    ):
        self.calls.append(
            "reevaluate"
        )

        self.arguments.append(
            {
                "cisa_kev_changed": (
                    cisa_kev_changed
                ),
                "github_advisory_changed": (
                    github_advisory_changed
                ),
                "epss_changed": (
                    epss_changed
                ),
                "evaluated_at": (
                    evaluated_at
                ),
            }
        )

        if self.should_fail:
            raise RuntimeError(
                "internal reprocessing failure"
            )

        return (
            ReevaluateThreatIntelligenceTargetsResult(
                cisa_kev_changed=(
                    cisa_kev_changed
                ),
                github_advisory_changed=(
                    github_advisory_changed
                ),
                epss_changed=(
                    epss_changed
                ),
                selected_target_count=2,
                processed_target_count=2,
                alert_transition_count=1,
                alert_evaluation_invoked_count=1,
            )
        )


def _service(
    *,
    calls,
    cisa_changed=True,
    github_changed=True,
    epss_changed=True,
):
    reevaluator = FakeReevaluator(
        calls=calls
    )

    service = (
        ThreatIntelligenceSchedulerCycleService(
            cisa_kev_stage=FakeStage(
                name="cisa",
                calls=calls,
                changed=cisa_changed,
                processed_count=10,
            ),
            github_advisory_stage=FakeStage(
                name="github",
                calls=calls,
                changed=github_changed,
                processed_count=20,
            ),
            epss_stage=FakeStage(
                name="epss",
                calls=calls,
                changed=epss_changed,
                processed_count=30,
            ),
            target_reevaluator=(
                reevaluator
            ),
        )
    )

    return (
        service,
        reevaluator,
    )


def test_cycle_runs_stages_in_order():
    calls = []

    service, reevaluator = _service(
        calls=calls
    )

    result = service.run(
        evaluated_at=EVALUATED_AT
    )

    assert calls == [
        "cisa",
        "github",
        "epss",
        "reevaluate",
    ]

    assert (
        result.cisa_kev.status
        == STAGE_STATUS_COMPLETED
    )

    assert (
        result.github_advisory.status
        == STAGE_STATUS_COMPLETED
    )

    assert (
        result.epss.status
        == STAGE_STATUS_COMPLETED
    )

    assert result.has_source_failures is False
    assert result.source_failure_count == 0

    assert (
        result.reprocessing
        .processed_target_count
        == 2
    )

    assert len(
        reevaluator.arguments
    ) == 1


def test_change_flags_are_forwarded():
    calls = []

    service, reevaluator = _service(
        calls=calls,
        cisa_changed=True,
        github_changed=False,
        epss_changed=True,
    )

    service.run(
        evaluated_at=EVALUATED_AT
    )

    arguments = (
        reevaluator.arguments[0]
    )

    assert (
        arguments[
            "cisa_kev_changed"
        ]
        is True
    )

    assert (
        arguments[
            "github_advisory_changed"
        ]
        is False
    )

    assert (
        arguments[
            "epss_changed"
        ]
        is True
    )


def test_no_changes_are_forwarded_without_failure():
    calls = []

    service, reevaluator = _service(
        calls=calls,
        cisa_changed=False,
        github_changed=False,
        epss_changed=False,
    )

    result = service.run(
        evaluated_at=EVALUATED_AT
    )

    arguments = (
        reevaluator.arguments[0]
    )

    assert (
        arguments[
            "cisa_kev_changed"
        ]
        is False
    )

    assert (
        arguments[
            "github_advisory_changed"
        ]
        is False
    )

    assert (
        arguments[
            "epss_changed"
        ]
        is False
    )

    assert (
        result.cisa_kev
        .processed_count
        == 10
    )

    assert (
        result.github_advisory
        .processed_count
        == 20
    )

    assert (
        result.epss
        .processed_count
        == 30
    )


def test_github_failure_does_not_block_epss_or_reprocessing():
    calls = []

    reevaluator = FakeReevaluator(
        calls=calls
    )

    service = (
        ThreatIntelligenceSchedulerCycleService(
            cisa_kev_stage=FakeStage(
                name="cisa",
                calls=calls,
                changed=True,
                processed_count=10,
            ),
            github_advisory_stage=(
                FailingStage(
                    name="github",
                    calls=calls,
                    message=(
                        "GitHub API timed out"
                    ),
                )
            ),
            epss_stage=FakeStage(
                name="epss",
                calls=calls,
                changed=True,
                processed_count=30,
            ),
            target_reevaluator=(
                reevaluator
            ),
        )
    )

    result = service.run(
        evaluated_at=EVALUATED_AT
    )

    assert calls == [
        "cisa",
        "github",
        "epss",
        "reevaluate",
    ]

    assert (
        result.cisa_kev.status
        == STAGE_STATUS_COMPLETED
    )

    assert (
        result.github_advisory.status
        == STAGE_STATUS_FAILED
    )

    assert (
        result.epss.status
        == STAGE_STATUS_COMPLETED
    )

    assert (
        result.github_advisory.changed
        is False
    )

    assert (
        result.github_advisory
        .processed_count
        == 0
    )

    assert (
        result.github_advisory
        .error_type
        == "RuntimeError"
    )

    assert (
        "GitHub API timed out"
        in (
            result
            .github_advisory
            .error_summary
            or ""
        )
    )

    assert result.has_source_failures is True
    assert result.source_failure_count == 1

    arguments = (
        reevaluator.arguments[0]
    )

    assert (
        arguments[
            "cisa_kev_changed"
        ]
        is True
    )

    assert (
        arguments[
            "github_advisory_changed"
        ]
        is False
    )

    assert (
        arguments[
            "epss_changed"
        ]
        is True
    )


def test_multiple_source_failures_do_not_stop_cycle():
    calls = []

    reevaluator = FakeReevaluator(
        calls=calls
    )

    service = (
        ThreatIntelligenceSchedulerCycleService(
            cisa_kev_stage=(
                FailingStage(
                    name="cisa",
                    calls=calls,
                )
            ),
            github_advisory_stage=(
                FailingStage(
                    name="github",
                    calls=calls,
                )
            ),
            epss_stage=FakeStage(
                name="epss",
                calls=calls,
                changed=True,
                processed_count=5,
            ),
            target_reevaluator=(
                reevaluator
            ),
        )
    )

    result = service.run(
        evaluated_at=EVALUATED_AT
    )

    assert calls == [
        "cisa",
        "github",
        "epss",
        "reevaluate",
    ]

    assert result.source_failure_count == 2

    arguments = (
        reevaluator.arguments[0]
    )

    assert (
        arguments[
            "cisa_kev_changed"
        ]
        is False
    )

    assert (
        arguments[
            "github_advisory_changed"
        ]
        is False
    )

    assert (
        arguments[
            "epss_changed"
        ]
        is True
    )


def test_invalid_stage_result_becomes_source_failure():
    calls = []

    reevaluator = FakeReevaluator(
        calls=calls
    )

    service = (
        ThreatIntelligenceSchedulerCycleService(
            cisa_kev_stage=(
                InvalidStage(
                    calls=calls,
                    name="cisa",
                )
            ), # pyright: ignore[reportArgumentType]
            github_advisory_stage=(
                FakeStage(
                    name="github",
                    calls=calls,
                    changed=False,
                    processed_count=0,
                )
            ),
            epss_stage=(
                FakeStage(
                    name="epss",
                    calls=calls,
                    changed=False,
                    processed_count=0,
                )
            ),
            target_reevaluator=(
                reevaluator
            ),
        )
    )

    result = service.run(
        evaluated_at=EVALUATED_AT
    )

    assert (
        result.cisa_kev.status
        == STAGE_STATUS_FAILED
    )

    assert (
        result.cisa_kev.error_type
        == "RuntimeError"
    )

    assert calls == [
        "cisa",
        "github",
        "epss",
        "reevaluate",
    ]


def test_internal_reprocessing_failure_still_propagates():
    calls = []

    reevaluator = FakeReevaluator(
        calls=calls,
        should_fail=True,
    )

    service = (
        ThreatIntelligenceSchedulerCycleService(
            cisa_kev_stage=FakeStage(
                name="cisa",
                calls=calls,
                changed=True,
                processed_count=1,
            ),
            github_advisory_stage=FakeStage(
                name="github",
                calls=calls,
                changed=True,
                processed_count=1,
            ),
            epss_stage=FakeStage(
                name="epss",
                calls=calls,
                changed=True,
                processed_count=1,
            ),
            target_reevaluator=(
                reevaluator
            ),
        )
    )

    try:
        service.run(
            evaluated_at=EVALUATED_AT
        )

    except RuntimeError as error:
        assert (
            str(error)
            == "internal reprocessing failure"
        )

    else:
        raise AssertionError(
            "Expected internal failure "
            "to propagate"
        )