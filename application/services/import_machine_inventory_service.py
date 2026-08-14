from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from application.models.machine_inventory_v1 import (
    MachineInventoryV1,
)
from application.ports.outbound.asset_inventory_unit_of_work import (
    AssetInventoryUnitOfWork,
)
from domain._asset_validation import (
    normalize_datetime_utc,
    validate_uuid,
)
from domain.machine import Machine
from domain.machine_inventory_state import (
    MachineInventoryState,
)
from domain.software_component import SoftwareComponent


class MachineInventoryImportError(
    RuntimeError
):
    pass


class OrganizationNotFoundError(
    MachineInventoryImportError
):
    pass


class OrganizationInactiveError(
    MachineInventoryImportError
):
    pass


class StaleMachineInventoryError(
    MachineInventoryImportError
):
    pass


class MachineInventoryTimestampConflictError(
    MachineInventoryImportError
):
    pass


class DuplicateInventoryComponentError(
    MachineInventoryImportError
):
    pass


@dataclass(
    frozen=True,
    slots=True,
)
class ImportMachineInventoryResult:
    machine_id: UUID
    inventory_id: UUID
    status: str
    machine_created: bool
    inserted_components: int
    updated_components: int
    deleted_components: int
    component_count: int


def _utc_now() -> datetime:
    return datetime.now(UTC)


class ImportMachineInventoryService:
    """
    Importe atomiquement un état observé inventory/v1.

    Le scanner fournit uniquement l'observation brute.
    L'organisation vient du contexte backend et jamais
    du payload.

    La réconciliation conserve les lignes existantes :
    - composant existant inchangé -> conservé ;
    - composant existant modifié -> UPDATE ;
    - nouveau composant -> INSERT ;
    - composant disparu -> DELETE ciblé.

    Aucun DELETE ALL + INSERT ALL.
    """

    def __init__(
        self,
        *,
        unit_of_work: AssetInventoryUnitOfWork,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        if unit_of_work is None:
            raise ValueError(
                "unit_of_work must not be None"
            )

        if clock is None:
            raise ValueError(
                "clock must not be None"
            )

        self._unit_of_work = unit_of_work
        self._clock = clock

    def import_inventory(
        self,
        *,
        organization_id: UUID,
        inventory_payload: (
            MachineInventoryV1
            | Mapping[str, Any]
        ),
    ) -> ImportMachineInventoryResult:
        normalized_organization_id = (
            validate_uuid(
                organization_id,
                field_name="organization_id",
            )
        )

        inventory = self._parse_inventory(
            inventory_payload
        )

        observed_components = (
            self._index_observed_components(
                inventory
            )
        )

        imported_at = normalize_datetime_utc(
            self._clock(),
            field_name="imported_at",
        )

        with self._unit_of_work as unit_of_work:
            repository = (
                unit_of_work.asset_inventory
            )

            organization = (
                repository.find_organization_by_id(
                    normalized_organization_id
                )
            )

            if organization is None:
                raise OrganizationNotFoundError(
                    "Organization does not exist"
                )

            if not organization.is_active:
                raise OrganizationInactiveError(
                    "Organization is inactive"
                )

            machine = (
                repository
                .find_machine_for_inventory_update(
                    organization_id=(
                        normalized_organization_id
                    ),
                    machine_uid=(
                        inventory.machine.machine_uid
                    ),
                )
            )

            machine_created = False

            if machine is None:
                machine_created = True

                machine = self._new_machine(
                    organization_id=(
                        normalized_organization_id
                    ),
                    inventory=inventory,
                    imported_at=imported_at,
                )

                repository.add_machine(
                    machine
                )

                current_state = None

            else:
                current_state = (
                    repository.find_inventory_state(
                        machine.id
                    )
                )

                idempotent_result = (
                    self._handle_replay_if_needed(
                        machine=machine,
                        inventory=inventory,
                        current_state=current_state,
                    )
                )

                if idempotent_result is not None:
                    return idempotent_result

                machine = self._updated_machine(
                    machine=machine,
                    inventory=inventory,
                    imported_at=imported_at,
                )

                repository.update_machine(
                    machine
                )

            existing_components = (
                repository.list_components(
                    machine.id
                )
            )

            (
                components_to_add,
                components_to_update,
                component_ids_to_delete,
            ) = self._reconcile_components(
                machine_id=machine.id,
                existing_components=(
                    existing_components
                ),
                observed_components=(
                    observed_components
                ),
                imported_at=imported_at,
            )

            if components_to_add:
                repository.add_components(
                    components_to_add
                )

            if components_to_update:
                repository.update_components(
                    components_to_update
                )

            if component_ids_to_delete:
                repository.delete_components(
                    machine_id=machine.id,
                    component_ids=(
                        component_ids_to_delete
                    ),
                )

            state = MachineInventoryState(
                machine_id=machine.id,
                inventory_id=(
                    inventory.inventory_id
                ),
                schema_version=(
                    inventory.schema_version
                ),
                collected_at=(
                    inventory.collected_at
                ),
                imported_at=imported_at,
                component_count=len(
                    inventory.components
                ),
            )

            repository.save_inventory_state(
                state
            )

            unit_of_work.commit()

            return ImportMachineInventoryResult(
                machine_id=machine.id,
                inventory_id=(
                    inventory.inventory_id
                ),
                status="imported",
                machine_created=machine_created,
                inserted_components=len(
                    components_to_add
                ),
                updated_components=len(
                    components_to_update
                ),
                deleted_components=len(
                    component_ids_to_delete
                ),
                component_count=len(
                    inventory.components
                ),
            )

    @staticmethod
    def _parse_inventory(
        payload: (
            MachineInventoryV1
            | Mapping[str, Any]
        ),
    ) -> MachineInventoryV1:
        if isinstance(
            payload,
            MachineInventoryV1,
        ):
            return payload

        if not isinstance(
            payload,
            Mapping,
        ):
            raise TypeError(
                "inventory_payload must be "
                "MachineInventoryV1 or mapping"
            )

        return MachineInventoryV1.from_mapping(
            payload
        )

    @staticmethod
    def _new_machine(
        *,
        organization_id: UUID,
        inventory: MachineInventoryV1,
        imported_at: datetime,
    ) -> Machine:
        return Machine(
            id=uuid4(),
            organization_id=organization_id,
            machine_uid=(
                inventory.machine.machine_uid
            ),
            hostname=(
                inventory.machine.hostname
            ),
            os_name=(
                inventory.machine.os_name
            ),
            os_version=(
                inventory.machine.os_version
            ),
            architecture=(
                inventory.machine.architecture
            ),
            last_inventory_at=(
                inventory.collected_at
            ),
            created_at=imported_at,
            updated_at=imported_at,
        )

    @staticmethod
    def _updated_machine(
        *,
        machine: Machine,
        inventory: MachineInventoryV1,
        imported_at: datetime,
    ) -> Machine:
        return replace(
            machine,
            hostname=(
                inventory.machine.hostname
            ),
            os_name=(
                inventory.machine.os_name
            ),
            os_version=(
                inventory.machine.os_version
            ),
            architecture=(
                inventory.machine.architecture
            ),
            last_inventory_at=(
                inventory.collected_at
            ),
            updated_at=imported_at,
        )

    @staticmethod
    def _handle_replay_if_needed(
        *,
        machine: Machine,
        inventory: MachineInventoryV1,
        current_state: (
            MachineInventoryState | None
        ),
    ) -> (
        ImportMachineInventoryResult | None
    ):
        if current_state is None:
            return None

        if (
            current_state.inventory_id
            == inventory.inventory_id
        ):
            return ImportMachineInventoryResult(
                machine_id=machine.id,
                inventory_id=(
                    inventory.inventory_id
                ),
                status="idempotent",
                machine_created=False,
                inserted_components=0,
                updated_components=0,
                deleted_components=0,
                component_count=(
                    current_state.component_count
                ),
            )

        if (
            inventory.collected_at
            < current_state.collected_at
        ):
            raise StaleMachineInventoryError(
                "Inventory collected_at is older "
                "than the current machine state"
            )

        if (
            inventory.collected_at
            == current_state.collected_at
        ):
            raise (
                MachineInventoryTimestampConflictError(
                    "Different inventory_id with the "
                    "same collected_at is not allowed"
                )
            )

        return None

    def _index_observed_components(
        self,
        inventory: MachineInventoryV1,
    ) -> dict[
        tuple[object, ...],
        object,
    ]:
        indexed: dict[
            tuple[object, ...],
            object,
        ] = {}

        for component in inventory.components:
            key = self._observed_key(
                component
            )

            if key in indexed:
                raise DuplicateInventoryComponentError(
                    "Duplicate component identity "
                    f"in inventory: {key!r}"
                )

            indexed[key] = component

        return indexed

    def _reconcile_components(
        self,
        *,
        machine_id: UUID,
        existing_components: list[
            SoftwareComponent
        ],
        observed_components: dict[
            tuple[object, ...],
            object,
        ],
        imported_at: datetime,
    ) -> tuple[
        list[SoftwareComponent],
        list[SoftwareComponent],
        list[UUID],
    ]:
        existing_by_key: dict[
            tuple[object, ...],
            SoftwareComponent,
        ] = {}

        for component in existing_components:
            key = self._stored_key(
                component
            )

            if key in existing_by_key:
                raise MachineInventoryImportError(
                    "Database contains duplicate "
                    f"component identity: {key!r}"
                )

            existing_by_key[key] = (
                component
            )

        components_to_add: list[
            SoftwareComponent
        ] = []

        components_to_update: list[
            SoftwareComponent
        ] = []

        for (
            key,
            observation,
        ) in observed_components.items():
            existing = existing_by_key.get(
                key
            )

            if existing is None:
                components_to_add.append(
                    self._new_component(
                        machine_id=machine_id,
                        observation=observation,
                        imported_at=(
                            imported_at
                        ),
                    )
                )

                continue

            updated = (
                self._updated_component_if_needed(
                    existing=existing,
                    observation=observation,
                    imported_at=imported_at,
                )
            )

            if updated is not None:
                components_to_update.append(
                    updated
                )

        component_ids_to_delete = [
            component.id
            for key, component
            in existing_by_key.items()
            if key not in observed_components
        ]

        return (
            components_to_add,
            components_to_update,
            component_ids_to_delete,
        )

    def _new_component(
        self,
        *,
        machine_id: UUID,
        observation: object,
        imported_at: datetime,
    ) -> SoftwareComponent:
        values = (
            self._observation_values(
                observation
            )
        )

        return SoftwareComponent(
            id=uuid4(),
            machine_id=machine_id,
            component_type=(
                values["component_type"]
            ),
            name=values["name"],
            normalized_name=None,
            version=values["version"],
            vendor=values["vendor"],
            normalized_vendor=None,
            ecosystem=values["ecosystem"],
            external_id=(
                values["external_id"]
            ),
            scope=values["scope"],
            detected_by=(
                values["detected_by"]
            ),
            created_at=imported_at,
            updated_at=imported_at,
        )

    def _updated_component_if_needed(
        self,
        *,
        existing: SoftwareComponent,
        observation: object,
        imported_at: datetime,
    ) -> SoftwareComponent | None:
        values = (
            self._observation_values(
                observation
            )
        )

        observed_raw_state = (
            values["component_type"],
            values["name"],
            values["version"],
            values["vendor"],
            values["ecosystem"],
            values["external_id"],
            values["scope"],
            values["detected_by"],
        )

        existing_raw_state = (
            existing.component_type,
            existing.name,
            existing.version,
            existing.vendor,
            existing.ecosystem,
            existing.external_id,
            existing.scope,
            existing.detected_by,
        )

        if (
            observed_raw_state
            == existing_raw_state
        ):
            return None

        name_changed = (
            existing.name
            != values["name"]
        )

        vendor_changed = (
            existing.vendor
            != values["vendor"]
        )

        return replace(
            existing,
            component_type=(
                values["component_type"]
            ),
            name=values["name"],
            normalized_name=(
                None
                if name_changed
                else existing.normalized_name
            ),
            version=values["version"],
            vendor=values["vendor"],
            normalized_vendor=(
                None
                if vendor_changed
                else existing.normalized_vendor
            ),
            ecosystem=values["ecosystem"],
            external_id=(
                values["external_id"]
            ),
            scope=values["scope"],
            detected_by=(
                values["detected_by"]
            ),
            updated_at=imported_at,
        )

    def _observed_key(
        self,
        component: object,
    ) -> tuple[object, ...]:
        component_type = getattr(
            component,
            "component_type",
        )

        detected_by = getattr(
            component,
            "detected_by",
        )

        if component_type == "application":
            return (
                "application",
                detected_by,
                getattr(
                    component,
                    "external_id",
                ),
            )

        if component_type == "package":
            return (
                "package",
                getattr(
                    component,
                    "ecosystem",
                ),
                getattr(
                    component,
                    "package_name",
                ),
                getattr(
                    component,
                    "scope",
                ),
                detected_by,
            )

        raise MachineInventoryImportError(
            "Unsupported component_type"
        )

    @staticmethod
    def _stored_key(
        component: SoftwareComponent,
    ) -> tuple[object, ...]:
        if (
            component.component_type
            == "application"
        ):
            return (
                "application",
                component.detected_by,
                component.external_id,
            )

        return (
            "package",
            component.ecosystem,
            component.name,
            component.scope,
            component.detected_by,
        )

    @staticmethod
    def _observation_values(
        component: object,
    ) -> dict[str, Any]:
        component_type = getattr(
            component,
            "component_type",
        )

        if component_type == "application":
            return {
                "component_type": (
                    "application"
                ),
                "name": getattr(
                    component,
                    "name",
                ),
                "version": getattr(
                    component,
                    "version",
                ),
                "vendor": getattr(
                    component,
                    "vendor",
                ),
                "ecosystem": None,
                "external_id": getattr(
                    component,
                    "external_id",
                ),
                "scope": None,
                "detected_by": getattr(
                    component,
                    "detected_by",
                ),
            }

        if component_type == "package":
            return {
                "component_type": "package",
                "name": getattr(
                    component,
                    "package_name",
                ),
                "version": getattr(
                    component,
                    "version",
                ),
                "vendor": None,
                "ecosystem": getattr(
                    component,
                    "ecosystem",
                ),
                "external_id": None,
                "scope": getattr(
                    component,
                    "scope",
                ),
                "detected_by": getattr(
                    component,
                    "detected_by",
                ),
            }

        raise MachineInventoryImportError(
            "Unsupported component_type"
        )