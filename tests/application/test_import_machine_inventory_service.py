from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import TracebackType
from uuid import UUID, uuid4

import pytest

from application.ports.outbound.asset_inventory_repository import (
    AssetInventoryRepository,
)
from application.services.import_machine_inventory_service import (
    ImportMachineInventoryService,
    MachineInventoryTimestampConflictError,
    StaleMachineInventoryError,
)
from domain.machine import Machine
from domain.machine_inventory_state import (
    MachineInventoryState,
)
from domain.organization import Organization
from domain.software_component import SoftwareComponent


NOW = datetime(
    2026,
    8,
    14,
    16,
    0,
    tzinfo=UTC,
)


class FakeAssetInventoryRepository:
    def __init__(
        self,
        organization: Organization,
    ) -> None:
        self.organization = organization

        self.machines: dict[
            UUID,
            Machine,
        ] = {}

        self.states: dict[
            UUID,
            MachineInventoryState,
        ] = {}

        self.components: dict[
            UUID,
            SoftwareComponent,
        ] = {}

    def find_organization_by_id(
        self,
        organization_id: UUID,
    ) -> Organization | None:
        if (
            self.organization.id
            == organization_id
        ):
            return self.organization

        return None

    def find_machine_for_inventory_update(
        self,
        *,
        organization_id: UUID,
        machine_uid: UUID,
    ) -> Machine | None:
        for machine in self.machines.values():
            if (
                machine.organization_id
                == organization_id
                and machine.machine_uid
                == machine_uid
            ):
                return machine

        return None

    def add_machine(
        self,
        machine: Machine,
    ) -> None:
        self.machines[machine.id] = machine

    def update_machine(
        self,
        machine: Machine,
    ) -> None:
        self.machines[machine.id] = machine

    def find_inventory_state(
        self,
        machine_id: UUID,
    ) -> MachineInventoryState | None:
        return self.states.get(
            machine_id
        )

    def save_inventory_state(
        self,
        state: MachineInventoryState,
    ) -> None:
        self.states[state.machine_id] = state

    def list_components(
        self,
        machine_id: UUID,
    ) -> list[SoftwareComponent]:
        return [
            component
            for component
            in self.components.values()
            if component.machine_id
            == machine_id
        ]

    def add_components(
        self,
        components: list[
            SoftwareComponent
        ],
    ) -> None:
        for component in components:
            self.components[
                component.id
            ] = component

    def update_components(
        self,
        components: list[
            SoftwareComponent
        ],
    ) -> None:
        for component in components:
            self.components[
                component.id
            ] = component

    def delete_components(
        self,
        *,
        machine_id: UUID,
        component_ids: list[UUID],
    ) -> None:
        for component_id in component_ids:
            component = (
                self.components.get(
                    component_id
                )
            )

            if (
                component is not None
                and component.machine_id
                == machine_id
            ):
                del self.components[
                    component_id
                ]


class FakeAssetInventoryUnitOfWork:
    def __init__(
        self,
        repository: (
            FakeAssetInventoryRepository
        ),
    ) -> None:
        self.asset_inventory = repository
        self.commit_count = 0
        self.rollback_count = 0

    def __enter__(
        self,
    ) -> FakeAssetInventoryUnitOfWork:
        return self

    def __exit__(
        self,
        exc_type: type[
            BaseException
        ] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        if exc_type is not None:
            self.rollback()

    def commit(
        self,
    ) -> None:
        self.commit_count += 1

    def rollback(
        self,
    ) -> None:
        self.rollback_count += 1


def _organization() -> Organization:
    return Organization(
        id=uuid4(),
        name="Example Organization",
        is_active=True,
        created_at=NOW,
    )


def _payload(
    *,
    machine_uid: UUID,
    inventory_id: UUID | None = None,
    collected_at: datetime = NOW,
    components: list[dict] | None = None,
) -> dict:
    return {
        "schema_version": "inventory/v1",
        "inventory_id": str(
            inventory_id or uuid4()
        ),
        "collected_at": (
            collected_at.isoformat()
        ),
        "agent": {
            "name": "tip-windows-agent",
            "version": "0.1.0",
        },
        "machine": {
            "machine_uid": str(
                machine_uid
            ),
            "hostname": "TEST-PC",
            "os_name": "Windows 11 Pro",
            "os_version": "25H2",
            "architecture": "x86_64",
        },
        "components": (
            components
            if components is not None
            else []
        ),
    }


def _application(
    *,
    name: str,
    version: str,
    external_id: str,
) -> dict:
    return {
        "component_type": "application",
        "name": name,
        "version": version,
        "vendor": "Example Vendor",
        "external_id": external_id,
        "detected_by": (
            "windows_registry_uninstall"
        ),
    }


def test_first_inventory_creates_machine_and_components() -> None:
    organization = _organization()

    repository = (
        FakeAssetInventoryRepository(
            organization
        )
    )

    unit_of_work = (
        FakeAssetInventoryUnitOfWork(
            repository
        )
    )

    service = ImportMachineInventoryService(
        unit_of_work=unit_of_work, # type: ignore
        clock=lambda: NOW,
    )

    machine_uid = uuid4()

    result = service.import_inventory(
        organization_id=organization.id,
        inventory_payload=_payload(
            machine_uid=machine_uid,
            components=[
                _application(
                    name="7-Zip",
                    version="24.09",
                    external_id="registry-7zip",
                )
            ],
        ),
    )

    assert result.status == "imported"
    assert result.machine_created is True
    assert result.inserted_components == 1
    assert result.updated_components == 0
    assert result.deleted_components == 0

    assert len(repository.machines) == 1
    assert len(repository.components) == 1
    assert len(repository.states) == 1

    assert unit_of_work.commit_count == 1


def test_same_inventory_id_is_idempotent() -> None:
    organization = _organization()

    repository = (
        FakeAssetInventoryRepository(
            organization
        )
    )

    unit_of_work = (
        FakeAssetInventoryUnitOfWork(
            repository
        )
    )

    service = ImportMachineInventoryService(
        unit_of_work=unit_of_work, # type: ignore
        clock=lambda: NOW,
    )

    machine_uid = uuid4()
    inventory_id = uuid4()

    payload = _payload(
        machine_uid=machine_uid,
        inventory_id=inventory_id,
        components=[
            _application(
                name="7-Zip",
                version="24.09",
                external_id="registry-7zip",
            )
        ],
    )

    service.import_inventory(
        organization_id=organization.id,
        inventory_payload=payload,
    )

    first_component_ids = set(
        repository.components
    )

    result = service.import_inventory(
        organization_id=organization.id,
        inventory_payload=payload,
    )

    assert result.status == "idempotent"

    assert set(
        repository.components
    ) == first_component_ids

    # Un seul commit : le replay est un no-op.
    assert unit_of_work.commit_count == 1


def test_older_inventory_is_rejected() -> None:
    organization = _organization()

    repository = (
        FakeAssetInventoryRepository(
            organization
        )
    )

    unit_of_work = (
        FakeAssetInventoryUnitOfWork(
            repository
        )
    )

    service = ImportMachineInventoryService(
        unit_of_work=unit_of_work, # type: ignore
        clock=lambda: NOW,
    )

    machine_uid = uuid4()

    service.import_inventory(
        organization_id=organization.id,
        inventory_payload=_payload(
            machine_uid=machine_uid,
            collected_at=NOW,
        ),
    )

    with pytest.raises(
        StaleMachineInventoryError
    ):
        service.import_inventory(
            organization_id=(
                organization.id
            ),
            inventory_payload=_payload(
                machine_uid=machine_uid,
                collected_at=(
                    NOW
                    - timedelta(minutes=1)
                ),
            ),
        )

    assert unit_of_work.commit_count == 1
    assert unit_of_work.rollback_count == 1


def test_same_timestamp_with_different_inventory_id_is_rejected() -> None:
    organization = _organization()

    repository = (
        FakeAssetInventoryRepository(
            organization
        )
    )

    unit_of_work = (
        FakeAssetInventoryUnitOfWork(
            repository
        )
    )

    service = ImportMachineInventoryService(
        unit_of_work=unit_of_work, # type: ignore
        clock=lambda: NOW,
    )

    machine_uid = uuid4()

    service.import_inventory(
        organization_id=organization.id,
        inventory_payload=_payload(
            machine_uid=machine_uid,
            collected_at=NOW,
        ),
    )

    with pytest.raises(
        MachineInventoryTimestampConflictError
    ):
        service.import_inventory(
            organization_id=(
                organization.id
            ),
            inventory_payload=_payload(
                machine_uid=machine_uid,
                collected_at=NOW,
            ),
        )


def test_reconciliation_updates_adds_and_deletes_without_replacing_everything() -> None:
    organization = _organization()

    repository = (
        FakeAssetInventoryRepository(
            organization
        )
    )

    unit_of_work = (
        FakeAssetInventoryUnitOfWork(
            repository
        )
    )

    later = NOW + timedelta(
        minutes=10
    )

    service = ImportMachineInventoryService(
        unit_of_work=unit_of_work, # type: ignore
        clock=lambda: later,
    )

    machine_uid = uuid4()

    service.import_inventory(
        organization_id=organization.id,
        inventory_payload=_payload(
            machine_uid=machine_uid,
            collected_at=NOW,
            components=[
                _application(
                    name="7-Zip",
                    version="24.08",
                    external_id="registry-7zip",
                ),
                _application(
                    name="Old App",
                    version="1.0",
                    external_id="registry-old",
                ),
            ],
        ),
    )

    original_7zip = next(
        component
        for component
        in repository.components.values()
        if component.external_id
        == "registry-7zip"
    )

    result = service.import_inventory(
        organization_id=organization.id,
        inventory_payload=_payload(
            machine_uid=machine_uid,
            collected_at=later,
            components=[
                _application(
                    name="7-Zip",
                    version="24.09",
                    external_id="registry-7zip",
                ),
                _application(
                    name="New App",
                    version="2.0",
                    external_id="registry-new",
                ),
            ],
        ),
    )

    assert result.inserted_components == 1
    assert result.updated_components == 1
    assert result.deleted_components == 1

    current_7zip = next(
        component
        for component
        in repository.components.values()
        if component.external_id
        == "registry-7zip"
    )

    # Même identité DB malgré le changement de version.
    assert (
        current_7zip.id
        == original_7zip.id
    )

    assert current_7zip.version == "24.09"

    assert {
        component.external_id
        for component
        in repository.components.values()
    } == {
        "registry-7zip",
        "registry-new",
    }