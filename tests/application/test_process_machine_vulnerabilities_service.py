from __future__ import annotations

from datetime import (
    UTC,
    datetime,
)
from uuid import (
    UUID,
    uuid4,
)

from application.ports.outbound.machine_vulnerability_processing_read_repository import (
    VulnerabilityExposureProcessingState,
)
from application.services.process_machine_vulnerabilities_service import (
    ProcessMachineVulnerabilitiesService,
)
from domain.software_component import (
    SoftwareComponent,
)


NOW = datetime(
    2026,
    8,
    18,
    14,
    0,
    tzinfo=UTC,
)


def _application(
    *,
    machine_id: UUID,
) -> SoftwareComponent:
    return SoftwareComponent(
        id=uuid4(),
        machine_id=machine_id,
        component_type="application",
        name="Example Browser",
        normalized_name=(
            "example browser"
        ),
        version="5.4.0",
        vendor="Example Corp",
        normalized_vendor=(
            "example corp"
        ),
        ecosystem=None,
        external_id=(
            f"registry-{uuid4()}"
        ),
        scope=None,
        detected_by=(
            "windows_registry_uninstall"
        ),
        created_at=NOW,
        updated_at=NOW,
    )


def _package(
    *,
    machine_id: UUID,
) -> SoftwareComponent:
    return SoftwareComponent(
        id=uuid4(),
        machine_id=machine_id,
        component_type="package",
        name="requests",
        normalized_name="requests",
        version="2.31.0",
        vendor=None,
        normalized_vendor=None,
        ecosystem="pypi",
        external_id=None,
        scope="global",
        detected_by="pip_global",
        created_at=NOW,
        updated_at=NOW,
    )


def _state(
    *,
    component_id: UUID,
    exposure_id: UUID | None = None,
    canonical_id: UUID | None = None,
    applicability_status: str = (
        "confirmed"
    ),
    priority: str | None = "HIGH",
    is_kev: bool = False,
) -> VulnerabilityExposureProcessingState:
    return (
        VulnerabilityExposureProcessingState(
            exposure_id=(
                exposure_id
                or uuid4()
            ),
            software_component_id=(
                component_id
            ),
            canonical_vulnerability_id=(
                canonical_id
                or uuid4()
            ),
            applicability_status=(
                applicability_status
            ),
            priority=priority,
            is_kev=is_kev,
        )
    )


class FakeReadRepository:
    def __init__(
        self,
        *,
        components: tuple[
            SoftwareComponent,
            ...,
        ],
        before: tuple[
            VulnerabilityExposureProcessingState,
            ...,
        ] = (),
        after: tuple[
            VulnerabilityExposureProcessingState,
            ...,
        ] = (),
        log: list[str] | None = None,
    ) -> None:
        self.components = components
        self.before = before
        self.after = after

        self.log = (
            log
            if log is not None
            else []
        )

        self.exposure_read_count = 0

    def find_machine_components(
        self,
        *,
        organization_id: UUID,
        machine_id: UUID,
    ) -> tuple[
        SoftwareComponent,
        ...,
    ]:
        del organization_id
        del machine_id

        self.log.append(
            "components"
        )

        return self.components

    def find_exposure_states(
        self,
        *,
        organization_id: UUID,
        machine_id: UUID,
        component_ids: tuple[
            UUID,
            ...,
        ],
    ) -> tuple[
        VulnerabilityExposureProcessingState,
        ...,
    ]:
        del organization_id
        del machine_id
        del component_ids

        self.exposure_read_count += 1

        if (
            self.exposure_read_count
            == 1
        ):
            self.log.append(
                "before"
            )

            return self.before

        self.log.append(
            "after"
        )

        return self.after


class FakeReconciler:
    def __init__(
        self,
        *,
        name: str,
        log: list[str],
    ) -> None:
        self.name = name
        self.log = log

        self.calls: list[
            dict[str, object]
        ] = []

    def reconcile(
        self,
        *,
        organization_id: UUID,
        machine_id: UUID,
        components: tuple[
            SoftwareComponent,
            ...,
        ],
        evaluated_at: datetime,
    ) -> object:
        self.log.append(
            self.name
        )

        self.calls.append(
            {
                "organization_id": (
                    organization_id
                ),
                "machine_id": (
                    machine_id
                ),
                "components": (
                    components
                ),
                "evaluated_at": (
                    evaluated_at
                ),
            }
        )

        return object()


class FakeEnricher:
    def __init__(
        self,
        *,
        name: str,
        log: list[str],
    ) -> None:
        self.name = name
        self.log = log

        self.calls: list[
            dict[str, object]
        ] = []

    def enrich(
        self,
        *,
        organization_id: UUID,
        machine_id: UUID,
        component_ids: tuple[
            UUID,
            ...,
        ],
    ) -> object:
        self.log.append(
            self.name
        )

        self.calls.append(
            {
                "organization_id": (
                    organization_id
                ),
                "machine_id": (
                    machine_id
                ),
                "component_ids": (
                    component_ids
                ),
            }
        )

        return object()


class FakeAlertEvaluator:
    def __init__(
        self,
        *,
        log: list[str],
    ) -> None:
        self.log = log

        self.calls: list[
            dict[str, object]
        ] = []

    def evaluate(
        self,
        *,
        organization_id: UUID,
        machine_id: UUID,
        transitions: tuple[
            object,
            ...,
        ],
        evaluated_at: datetime,
    ) -> object:
        self.log.append(
            "alerts"
        )

        self.calls.append(
            {
                "organization_id": (
                    organization_id
                ),
                "machine_id": (
                    machine_id
                ),
                "transitions": (
                    transitions
                ),
                "evaluated_at": (
                    evaluated_at
                ),
            }
        )

        return object()


def _service(
    *,
    reader: FakeReadRepository,
    log: list[str],
) -> tuple[
    ProcessMachineVulnerabilitiesService,
    FakeReconciler,
    FakeReconciler,
    FakeEnricher,
    FakeEnricher,
    FakeAlertEvaluator,
]:
    package = FakeReconciler(
        name="package",
        log=log,
    )

    cisa = FakeReconciler(
        name="cisa",
        log=log,
    )

    severity = FakeEnricher(
        name="severity",
        log=log,
    )

    priority = FakeEnricher(
        name="priority",
        log=log,
    )

    alerts = FakeAlertEvaluator(
        log=log,
    )

    service = (
        ProcessMachineVulnerabilitiesService(
            read_repository=reader,
            package_reconciler=package,
            cisa_kev_reconciler=cisa,
            severity_enricher=severity,
            priority_enricher=priority,
            alert_evaluator=alerts,
        )
    )

    return (
        service,
        package,
        cisa,
        severity,
        priority,
        alerts,
    )


def test_processes_full_machine_pipeline_in_correct_order(
) -> None:
    organization_id = uuid4()
    machine_id = uuid4()

    package_component = _package(
        machine_id=machine_id
    )

    application_component = (
        _application(
            machine_id=machine_id
        )
    )

    existing_exposure_id = (
        uuid4()
    )

    existing_canonical_id = (
        uuid4()
    )

    before_existing = _state(
        component_id=(
            package_component.id
        ),
        exposure_id=(
            existing_exposure_id
        ),
        canonical_id=(
            existing_canonical_id
        ),
        priority="HIGH",
        is_kev=False,
    )

    after_existing = _state(
        component_id=(
            package_component.id
        ),
        exposure_id=(
            existing_exposure_id
        ),
        canonical_id=(
            existing_canonical_id
        ),
        priority="CRITICAL",
        is_kev=True,
    )

    after_new = _state(
        component_id=(
            application_component.id
        ),
        priority="HIGH",
        applicability_status=(
            "potential"
        ),
        is_kev=True,
    )

    log: list[str] = []

    reader = FakeReadRepository(
        components=(
            package_component,
            application_component,
        ),
        before=(
            before_existing,
        ),
        after=(
            after_existing,
            after_new,
        ),
        log=log,
    )

    (
        service,
        package,
        cisa,
        severity,
        priority,
        alerts,
    ) = _service(
        reader=reader,
        log=log,
    )

    result = service.process(
        organization_id=organization_id,
        machine_id=machine_id,
        evaluated_at=NOW,
    )

    assert log == [
        "components",
        "before",
        "package",
        "cisa",
        "severity",
        "priority",
        "after",
        "alerts",
    ]

    assert result.component_count == 2
    assert result.package_count == 1

    assert (
        result.application_count
        == 1
    )

    assert (
        result.before_exposure_count
        == 1
    )

    assert (
        result.after_exposure_count
        == 2
    )

    assert (
        result.new_exposure_count
        == 1
    )

    assert (
        result.existing_exposure_count
        == 1
    )

    assert (
        result.alert_transition_count
        == 2
    )

    assert (
        result.alert_evaluation_invoked
        is True
    )

    assert len(
        package.calls
    ) == 1

    assert len(
        cisa.calls
    ) == 1

    assert len(
        severity.calls
    ) == 1

    assert len(
        priority.calls
    ) == 1

    assert len(
        alerts.calls
    ) == 1


def test_empty_machine_is_noop(
) -> None:
    organization_id = uuid4()
    machine_id = uuid4()

    log: list[str] = []

    reader = FakeReadRepository(
        components=(),
        log=log,
    )

    (
        service,
        package,
        cisa,
        severity,
        priority,
        alerts,
    ) = _service(
        reader=reader,
        log=log,
    )

    result = service.process(
        organization_id=organization_id,
        machine_id=machine_id,
        evaluated_at=NOW,
    )

    assert log == [
        "components",
    ]

    assert result.component_count == 0

    assert (
        result.alert_transition_count
        == 0
    )

    assert (
        result.alert_evaluation_invoked
        is False
    )

    assert package.calls == []
    assert cisa.calls == []
    assert severity.calls == []
    assert priority.calls == []
    assert alerts.calls == []


def test_new_exposure_creates_new_alert_transition(
) -> None:
    organization_id = uuid4()
    machine_id = uuid4()

    package_component = _package(
        machine_id=machine_id
    )

    new_state = _state(
        component_id=(
            package_component.id
        ),
        priority="CRITICAL",
        is_kev=False,
    )

    log: list[str] = []

    reader = FakeReadRepository(
        components=(
            package_component,
        ),
        before=(),
        after=(
            new_state,
        ),
        log=log,
    )

    (
        service,
        _,
        _,
        _,
        _,
        alerts,
    ) = _service(
        reader=reader,
        log=log,
    )

    service.process(
        organization_id=organization_id,
        machine_id=machine_id,
        evaluated_at=NOW,
    )

    assert len(
        alerts.calls
    ) == 1

    transitions = (
        alerts.calls[0][
            "transitions"
        ]
    )

    assert isinstance(
        transitions,
        tuple,
    )

    assert len(
        transitions
    ) == 1

    transition = transitions[0]

    assert (
        transition.exposure_id
        == new_state.exposure_id
    )

    assert (
        transition.is_new_exposure
        is True
    )

    assert (
        transition.previous_priority
        is None
    )

    assert (
        transition.current_priority
        == "CRITICAL"
    )

    assert (
        transition.previous_is_kev
        is False
    )


def test_existing_exposure_preserves_before_and_after_signals(
) -> None:
    organization_id = uuid4()
    machine_id = uuid4()

    package_component = _package(
        machine_id=machine_id
    )

    exposure_id = uuid4()
    canonical_id = uuid4()

    before = _state(
        component_id=(
            package_component.id
        ),
        exposure_id=exposure_id,
        canonical_id=canonical_id,
        priority="HIGH",
        is_kev=False,
    )

    after = _state(
        component_id=(
            package_component.id
        ),
        exposure_id=exposure_id,
        canonical_id=canonical_id,
        priority="CRITICAL",
        is_kev=True,
    )

    log: list[str] = []

    reader = FakeReadRepository(
        components=(
            package_component,
        ),
        before=(
            before,
        ),
        after=(
            after,
        ),
        log=log,
    )

    (
        service,
        _,
        _,
        _,
        _,
        alerts,
    ) = _service(
        reader=reader,
        log=log,
    )

    service.process(
        organization_id=organization_id,
        machine_id=machine_id,
        evaluated_at=NOW,
    )

    transitions = (
        alerts.calls[0][
            "transitions"
        ]
    )

    assert isinstance(
        transitions,
        tuple,
    )

    transition = transitions[0]

    assert (
        transition.is_new_exposure
        is False
    )

    assert (
        transition.previous_priority
        == "HIGH"
    )

    assert (
        transition.current_priority
        == "CRITICAL"
    )

    assert (
        transition.previous_is_kev
        is False
    )

    assert (
        transition.current_is_kev
        is True
    )


def test_disappeared_exposure_does_not_create_alert_transition(
) -> None:
    organization_id = uuid4()
    machine_id = uuid4()

    package_component = _package(
        machine_id=machine_id
    )

    disappeared = _state(
        component_id=(
            package_component.id
        ),
        priority="CRITICAL",
        is_kev=True,
    )

    log: list[str] = []

    reader = FakeReadRepository(
        components=(
            package_component,
        ),
        before=(
            disappeared,
        ),
        after=(),
        log=log,
    )

    (
        service,
        _,
        _,
        _,
        _,
        alerts,
    ) = _service(
        reader=reader,
        log=log,
    )

    result = service.process(
        organization_id=organization_id,
        machine_id=machine_id,
        evaluated_at=NOW,
    )

    assert (
        result.before_exposure_count
        == 1
    )

    assert (
        result.after_exposure_count
        == 0
    )

    assert (
        result.alert_transition_count
        == 0
    )

    assert (
        result.alert_evaluation_invoked
        is False
    )

    assert alerts.calls == []