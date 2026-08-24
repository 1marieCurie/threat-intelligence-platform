from __future__ import annotations

from datetime import (
    datetime,
    timezone,
)
from uuid import uuid4

import pytest

from application.ports.outbound.threat_intelligence_reprocessing_target_repository import (
    ThreatIntelligenceReprocessingTarget,
)
from application.services.process_machine_vulnerabilities_service import (
    ProcessMachineVulnerabilitiesResult,
)
from application.services.reevaluate_threat_intelligence_targets_service import (
    ReevaluateThreatIntelligenceTargetsService,
)


class FakeTargetRepository:
    def __init__(
        self,
        *,
        application_targets=(),
        package_targets=(),
        exposure_targets=(),
    ) -> None:
        self.application_targets = (
            application_targets
        )
        self.package_targets = (
            package_targets
        )
        self.exposure_targets = (
            exposure_targets
        )

        self.application_calls = 0
        self.package_calls = 0
        self.exposure_calls = 0

    def find_application_targets(
        self,
    ):
        self.application_calls += 1
        return self.application_targets

    def find_package_targets(
        self,
    ):
        self.package_calls += 1
        return self.package_targets

    def find_exposure_targets(
        self,
    ):
        self.exposure_calls += 1
        return self.exposure_targets


class FakeMachineProcessor:
    def __init__(self) -> None:
        self.calls = []

    def process(
        self,
        *,
        organization_id,
        machine_id,
        evaluated_at,
    ):
        self.calls.append(
            (
                organization_id,
                machine_id,
                evaluated_at,
            )
        )

        return (
            ProcessMachineVulnerabilitiesResult(
                organization_id=(
                    organization_id
                ),
                machine_id=machine_id,
                component_count=1,
                package_count=1,
                application_count=0,
                before_exposure_count=1,
                after_exposure_count=1,
                new_exposure_count=0,
                existing_exposure_count=1,
                alert_transition_count=1,
                alert_evaluation_invoked=True,
            )
        )


def _target(
    organization_id=None,
    machine_id=None,
):
    return (
        ThreatIntelligenceReprocessingTarget(
            organization_id=(
                organization_id
                or uuid4()
            ),
            machine_id=(
                machine_id
                or uuid4()
            ),
        )
    )


def _evaluated_at():
    return datetime(
        2026,
        8,
        23,
        20,
        0,
        0,
        tzinfo=timezone.utc,
    )


def test_no_change_does_not_query_targets():
    repository = FakeTargetRepository()
    processor = FakeMachineProcessor()

    service = (
        ReevaluateThreatIntelligenceTargetsService(
            target_repository=repository,
            machine_processor=processor,
        )
    )

    result = service.reevaluate(
        cisa_kev_changed=False,
        github_advisory_changed=False,
        epss_changed=False,
        evaluated_at=_evaluated_at(),
    )

    assert result.selected_target_count == 0
    assert result.processed_target_count == 0
    assert result.alert_transition_count == 0

    assert repository.application_calls == 0
    assert repository.package_calls == 0
    assert repository.exposure_calls == 0

    assert processor.calls == []


def test_cisa_change_reprocesses_applications_and_exposures():
    organization_id = uuid4()

    application_target = _target(
        organization_id=organization_id,
    )

    exposure_target = _target(
        organization_id=organization_id,
    )

    repository = FakeTargetRepository(
        application_targets=(
            application_target,
        ),
        exposure_targets=(
            exposure_target,
        ),
    )

    processor = FakeMachineProcessor()

    service = (
        ReevaluateThreatIntelligenceTargetsService(
            target_repository=repository,
            machine_processor=processor,
        )
    )

    result = service.reevaluate(
        cisa_kev_changed=True,
        github_advisory_changed=False,
        epss_changed=False,
        evaluated_at=_evaluated_at(),
    )

    assert result.selected_target_count == 2
    assert result.processed_target_count == 2
    assert result.alert_transition_count == 2
    assert (
        result.alert_evaluation_invoked_count
        == 2
    )

    assert repository.application_calls == 1
    assert repository.package_calls == 0
    assert repository.exposure_calls == 1

    assert len(processor.calls) == 2


def test_duplicate_targets_are_processed_once():
    organization_id = uuid4()
    machine_id = uuid4()

    duplicate = _target(
        organization_id=organization_id,
        machine_id=machine_id,
    )

    repository = FakeTargetRepository(
        application_targets=(
            duplicate,
        ),
        package_targets=(
            duplicate,
        ),
        exposure_targets=(
            duplicate,
        ),
    )

    processor = FakeMachineProcessor()

    service = (
        ReevaluateThreatIntelligenceTargetsService(
            target_repository=repository,
            machine_processor=processor,
        )
    )

    result = service.reevaluate(
        cisa_kev_changed=True,
        github_advisory_changed=True,
        epss_changed=True,
        evaluated_at=_evaluated_at(),
    )

    assert result.selected_target_count == 1
    assert result.processed_target_count == 1
    assert len(processor.calls) == 1


def test_github_change_uses_package_targets():
    package_target = _target()

    repository = FakeTargetRepository(
        package_targets=(
            package_target,
        ),
    )

    processor = FakeMachineProcessor()

    service = (
        ReevaluateThreatIntelligenceTargetsService(
            target_repository=repository,
            machine_processor=processor,
        )
    )

    result = service.reevaluate(
        cisa_kev_changed=False,
        github_advisory_changed=True,
        epss_changed=False,
        evaluated_at=_evaluated_at(),
    )

    assert result.selected_target_count == 1
    assert repository.application_calls == 0
    assert repository.package_calls == 1
    assert repository.exposure_calls == 0


def test_epss_change_uses_existing_exposures():
    exposure_target = _target()

    repository = FakeTargetRepository(
        exposure_targets=(
            exposure_target,
        ),
    )

    processor = FakeMachineProcessor()

    service = (
        ReevaluateThreatIntelligenceTargetsService(
            target_repository=repository,
            machine_processor=processor,
        )
    )

    result = service.reevaluate(
        cisa_kev_changed=False,
        github_advisory_changed=False,
        epss_changed=True,
        evaluated_at=_evaluated_at(),
    )

    assert result.selected_target_count == 1
    assert repository.application_calls == 0
    assert repository.package_calls == 0
    assert repository.exposure_calls == 1


def test_change_flags_must_be_boolean():
    repository = FakeTargetRepository()
    processor = FakeMachineProcessor()

    service = (
        ReevaluateThreatIntelligenceTargetsService(
            target_repository=repository,
            machine_processor=processor,
        )
    )

    with pytest.raises(
        TypeError,
        match=(
            "cisa_kev_changed must be "
            "a boolean"
        ),
    ):
        service.reevaluate(
            cisa_kev_changed=1, # type: ignore
            github_advisory_changed=False,
            epss_changed=False,
            evaluated_at=_evaluated_at(),
        )