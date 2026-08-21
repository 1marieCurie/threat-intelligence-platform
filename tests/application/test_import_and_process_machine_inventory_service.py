from __future__ import annotations

from datetime import (
    UTC,
    datetime,
)
from unittest.mock import (
    Mock,
)
from uuid import (
    uuid4,
)

import pytest

from application.services.import_and_process_machine_inventory_service import (
    ImportAndProcessMachineInventoryService,
)
from application.services.import_machine_inventory_service import (
    ImportMachineInventoryResult,
    ImportMachineInventoryService,
    StaleMachineInventoryError,
)
from application.services.process_machine_vulnerabilities_service import (
    ProcessMachineVulnerabilitiesError,
    ProcessMachineVulnerabilitiesService,
)


NOW = datetime(
    2026,
    8,
    20,
    15,
    30,
    tzinfo=UTC,
)


def _import_result(
    *,
    status: str = "imported",
    machine_created: bool = False,
) -> ImportMachineInventoryResult:
    return ImportMachineInventoryResult(
        machine_id=uuid4(),
        inventory_id=uuid4(),
        status=status,
        machine_created=(
            machine_created
        ),
        inserted_components=5,
        updated_components=2,
        deleted_components=1,
        component_count=10,
    )


def _services(
) -> tuple[
    Mock,
    Mock,
]:
    import_service = Mock(
        spec=(
            ImportMachineInventoryService
        )
    )

    processing_service = Mock(
        spec=(
            ProcessMachineVulnerabilitiesService
        )
    )

    return (
        import_service,
        processing_service,
    )


def test_import_then_processes_machine_vulnerabilities(
) -> None:
    (
        import_service,
        processing_service,
    ) = _services()

    organization_id = uuid4()

    payload = {
        "schema_version": (
            "inventory/v1"
        ),
    }

    import_result = (
        _import_result(
            machine_created=True,
        )
    )

    import_service.import_inventory.return_value = (
        import_result
    )

    service = (
        ImportAndProcessMachineInventoryService(
            import_service=(
                import_service
            ),
            vulnerability_processing_service=(
                processing_service
            ),
            clock=lambda: NOW,
        )
    )

    result = service.import_inventory(
        organization_id=(
            organization_id
        ),
        inventory_payload=(
            payload
        ),
    )

    (
        import_service
        .import_inventory
        .assert_called_once_with(
            organization_id=(
                organization_id
            ),
            inventory_payload=(
                payload
            ),
        )
    )

    (
        processing_service
        .process
        .assert_called_once_with(
            organization_id=(
                organization_id
            ),
            machine_id=(
                import_result.machine_id
            ),
            evaluated_at=NOW,
        )
    )

    assert (
        result
        is import_result
    )


def test_idempotent_inventory_still_reprocesses_vulnerabilities(
) -> None:
    (
        import_service,
        processing_service,
    ) = _services()

    organization_id = uuid4()

    payload = {
        "schema_version": (
            "inventory/v1"
        ),
    }

    import_result = (
        _import_result(
            status="idempotent",
            machine_created=False,
        )
    )

    import_result = (
        ImportMachineInventoryResult(
            machine_id=(
                import_result.machine_id
            ),
            inventory_id=(
                import_result.inventory_id
            ),
            status="idempotent",
            machine_created=False,
            inserted_components=0,
            updated_components=0,
            deleted_components=0,
            component_count=10,
        )
    )

    import_service.import_inventory.return_value = (
        import_result
    )

    service = (
        ImportAndProcessMachineInventoryService(
            import_service=(
                import_service
            ),
            vulnerability_processing_service=(
                processing_service
            ),
            clock=lambda: NOW,
        )
    )

    result = service.import_inventory(
        organization_id=(
            organization_id
        ),
        inventory_payload=(
            payload
        ),
    )

    assert (
        result.status
        == "idempotent"
    )

    assert (
        result.inserted_components
        == 0
    )

    assert (
        result.updated_components
        == 0
    )

    assert (
        result.deleted_components
        == 0
    )

    (
        processing_service
        .process
        .assert_called_once_with(
            organization_id=(
                organization_id
            ),
            machine_id=(
                import_result.machine_id
            ),
            evaluated_at=NOW,
        )
    )


def test_import_failure_does_not_process_vulnerabilities(
) -> None:
    (
        import_service,
        processing_service,
    ) = _services()

    organization_id = uuid4()

    payload = {
        "schema_version": (
            "inventory/v1"
        ),
    }

    import_service.import_inventory.side_effect = (
        StaleMachineInventoryError(
            "Inventory is stale"
        )
    )

    service = (
        ImportAndProcessMachineInventoryService(
            import_service=(
                import_service
            ),
            vulnerability_processing_service=(
                processing_service
            ),
            clock=lambda: NOW,
        )
    )

    with pytest.raises(
        StaleMachineInventoryError
    ):
        service.import_inventory(
            organization_id=(
                organization_id
            ),
            inventory_payload=(
                payload
            ),
        )

    (
        processing_service
        .process
        .assert_not_called()
    )


def test_processing_failure_is_propagated_after_successful_import(
) -> None:
    (
        import_service,
        processing_service,
    ) = _services()

    organization_id = uuid4()

    payload = {
        "schema_version": (
            "inventory/v1"
        ),
    }

    import_result = (
        _import_result()
    )

    import_service.import_inventory.return_value = (
        import_result
    )

    processing_service.process.side_effect = (
        ProcessMachineVulnerabilitiesError(
            "Vulnerability processing failed"
        )
    )

    service = (
        ImportAndProcessMachineInventoryService(
            import_service=(
                import_service
            ),
            vulnerability_processing_service=(
                processing_service
            ),
            clock=lambda: NOW,
        )
    )

    with pytest.raises(
        ProcessMachineVulnerabilitiesError
    ):
        service.import_inventory(
            organization_id=(
                organization_id
            ),
            inventory_payload=(
                payload
            ),
        )

    (
        import_service
        .import_inventory
        .assert_called_once()
    )

    (
        processing_service
        .process
        .assert_called_once_with(
            organization_id=(
                organization_id
            ),
            machine_id=(
                import_result.machine_id
            ),
            evaluated_at=NOW,
        )
    )


def test_constructor_rejects_missing_import_service(
) -> None:
    (
        _,
        processing_service,
    ) = _services()

    with pytest.raises(
        ValueError,
        match=(
            "import_service "
            "must not be None"
        ),
    ):
        ImportAndProcessMachineInventoryService(
            import_service=None,  # type: ignore[arg-type]
            vulnerability_processing_service=(
                processing_service
            ),
        )


def test_constructor_rejects_missing_processing_service(
) -> None:
    (
        import_service,
        _,
    ) = _services()

    with pytest.raises(
        ValueError,
        match=(
            "vulnerability_processing_service "
            "must not be None"
        ),
    ):
        ImportAndProcessMachineInventoryService(
            import_service=(
                import_service
            ),
            vulnerability_processing_service=None,  # type: ignore[arg-type]
        )