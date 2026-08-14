from __future__ import annotations

from collections.abc import Sequence
from uuid import UUID

from sqlalchemy import delete, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from application.ports.outbound.asset_inventory_repository import (
    AssetInventoryRepositoryError,
)
from sqlalchemy.exc import (
    IntegrityError,
    SQLAlchemyError,
)
from application.ports.outbound.asset_inventory_repository import (
    AssetInventoryConflictError,
    AssetInventoryRepositoryError,
)
from domain.machine import Machine
from domain.machine_inventory_state import (
    MachineInventoryState,
)
from domain.organization import Organization
from domain.software_component import SoftwareComponent
from infrastructure.persistence.models.assets import (
    MachineInventoryStateModel,
    MachineModel,
    OrganizationModel,
    SoftwareComponentModel,
)


class SqlAlchemyAssetInventoryRepository:
    """
    Persistance SQLAlchemy de l'inventaire machine.

    Le repository ne commit jamais.
    La transaction appartient à la Unit of Work.
    """

    def __init__(
        self,
        *,
        session: Session,
    ) -> None:
        if session is None:
            raise ValueError(
                "session must not be None"
            )

        self._session = session

        self._machine_models: dict[
            UUID,
            MachineModel,
        ] = {}

        self._state_models: dict[
            UUID,
            MachineInventoryStateModel | None,
        ] = {}

        self._component_models: dict[
            UUID,
            SoftwareComponentModel,
        ] = {}

    def find_organization_by_id(
        self,
        organization_id: UUID,
    ) -> Organization | None:
        try:
            model = self._session.scalar(
                select(
                    OrganizationModel
                ).where(
                    OrganizationModel.id
                    == organization_id
                )
            )

        except SQLAlchemyError as error:
            raise AssetInventoryRepositoryError(
                "Unable to read organization"
            ) from error

        if model is None:
            return None

        return self._to_organization(
            model
        )

    def find_machine_for_inventory_update(
        self,
        *,
        organization_id: UUID,
        machine_uid: UUID,
    ) -> Machine | None:
        try:
            model = self._session.scalar(
                select(
                    MachineModel
                )
                .where(
                    MachineModel.organization_id
                    == organization_id,
                    MachineModel.machine_uid
                    == machine_uid,
                )
                .with_for_update()
            )

        except SQLAlchemyError as error:
            raise AssetInventoryRepositoryError(
                "Unable to read machine "
                "for inventory update"
            ) from error

        if model is None:
            return None

        self._machine_models[
            model.id
        ] = model

        return self._to_machine(
            model
        )

    def add_machine(
        self,
        machine: Machine,
    ) -> None:
        model = MachineModel(
            id=machine.id,
            organization_id=(
                machine.organization_id
            ),
            machine_uid=machine.machine_uid,
            hostname=machine.hostname,
            os_name=machine.os_name,
            os_version=machine.os_version,
            architecture=machine.architecture,
            last_inventory_at=(
                machine.last_inventory_at
            ),
            created_at=machine.created_at,
            updated_at=machine.updated_at,
        )

        self._session.add(model)

        try:
            # Important :
            #
            # Les modèles asset n'utilisent volontairement
            # aucune relationship() ORM.
            #
            # On matérialise donc explicitement la nouvelle
            # machine dans la transaction avant d'ajouter
            # machine_inventory_state et software_component,
            # qui portent des FK vers machine.id.
            #
            # flush() != commit().
            self._session.flush()

        except IntegrityError as error:
            raise AssetInventoryConflictError(
                "Machine creation conflicts "
                "with an existing database identity"
            ) from error

        except SQLAlchemyError as error:
            raise AssetInventoryRepositoryError(
                "Unable to persist new machine"
            ) from error

        self._machine_models[
            machine.id
        ] = model

        # Une machine qui vient d'être créée ne peut pas
        # encore posséder de current inventory state.
        # Ce cache évite un SELECT inutile plus tard dans
        # save_inventory_state().
        self._state_models[
            machine.id
        ] = None

    def update_machine(
        self,
        machine: Machine,
    ) -> None:
        model = self._machine_models.get(
            machine.id
        )

        if model is None:
            try:
                model = self._session.scalar(
                    select(
                        MachineModel
                    )
                    .where(
                        MachineModel.id
                        == machine.id,
                        MachineModel.organization_id
                        == machine.organization_id,
                    )
                    .with_for_update()
                )

            except SQLAlchemyError as error:
                raise AssetInventoryRepositoryError(
                    "Unable to load machine "
                    "for update"
                ) from error

        if model is None:
            raise AssetInventoryRepositoryError(
                "Machine to update does not exist"
            )

        model.hostname = machine.hostname
        model.os_name = machine.os_name
        model.os_version = (
            machine.os_version
        )
        model.architecture = (
            machine.architecture
        )
        model.last_inventory_at = (
            machine.last_inventory_at
        )
        model.updated_at = machine.updated_at

        self._machine_models[
            machine.id
        ] = model

    def find_inventory_state(
        self,
        machine_id: UUID,
    ) -> MachineInventoryState | None:
        try:
            model = self._session.get(
                MachineInventoryStateModel,
                machine_id,
            )

        except SQLAlchemyError as error:
            raise AssetInventoryRepositoryError(
                "Unable to read machine "
                "inventory state"
            ) from error

        self._state_models[
            machine_id
        ] = model

        if model is None:
            return None

        return self._to_inventory_state(
            model
        )

    def save_inventory_state(
        self,
        state: MachineInventoryState,
    ) -> None:
        if (
            state.machine_id
            in self._state_models
        ):
            model = self._state_models[
                state.machine_id
            ]
        else:
            try:
                model = self._session.get(
                    MachineInventoryStateModel,
                    state.machine_id,
                )

            except SQLAlchemyError as error:
                raise AssetInventoryRepositoryError(
                    "Unable to load inventory "
                    "state for persistence"
                ) from error

        if model is None:
            model = (
                MachineInventoryStateModel(
                    machine_id=state.machine_id,
                    inventory_id=(
                        state.inventory_id
                    ),
                    schema_version=(
                        state.schema_version
                    ),
                    collected_at=(
                        state.collected_at
                    ),
                    imported_at=(
                        state.imported_at
                    ),
                    component_count=(
                        state.component_count
                    ),
                )
            )

            self._session.add(model)

        else:
            model.inventory_id = (
                state.inventory_id
            )
            model.schema_version = (
                state.schema_version
            )
            model.collected_at = (
                state.collected_at
            )
            model.imported_at = (
                state.imported_at
            )
            model.component_count = (
                state.component_count
            )

        self._state_models[
            state.machine_id
        ] = model

    def list_components(
        self,
        machine_id: UUID,
    ) -> list[SoftwareComponent]:
        try:
            models = list(
                self._session.scalars(
                    select(
                        SoftwareComponentModel
                    )
                    .where(
                        SoftwareComponentModel.machine_id
                        == machine_id
                    )
                    .order_by(
                        SoftwareComponentModel.id
                    )
                )
            )

        except SQLAlchemyError as error:
            raise AssetInventoryRepositoryError(
                "Unable to read software components"
            ) from error

        for model in models:
            self._component_models[
                model.id
            ] = model

        return [
            self._to_component(model)
            for model in models
        ]

    def add_components(
        self,
        components: Sequence[
            SoftwareComponent
        ],
    ) -> None:
        if not components:
            return

        models: list[
            SoftwareComponentModel
        ] = []

        for component in components:
            model = self._component_model(
                component
            )

            models.append(model)

            self._component_models[
                component.id
            ] = model

        self._session.add_all(
            models
        )

    def update_components(
        self,
        components: Sequence[
            SoftwareComponent
        ],
    ) -> None:
        if not components:
            return

        missing_ids = [
            component.id
            for component in components
            if component.id
            not in self._component_models
        ]

        if missing_ids:
            try:
                models = list(
                    self._session.scalars(
                        select(
                            SoftwareComponentModel
                        ).where(
                            SoftwareComponentModel.id.in_(
                                missing_ids
                            )
                        )
                    )
                )

            except SQLAlchemyError as error:
                raise AssetInventoryRepositoryError(
                    "Unable to load software "
                    "components for update"
                ) from error

            for model in models:
                self._component_models[
                    model.id
                ] = model

        for component in components:
            model = (
                self._component_models.get(
                    component.id
                )
            )

            if model is None:
                raise AssetInventoryRepositoryError(
                    "Software component to "
                    "update does not exist"
                )

            if (
                model.machine_id
                != component.machine_id
            ):
                raise AssetInventoryRepositoryError(
                    "Software component machine "
                    "scope mismatch"
                )

            self._apply_component(
                model=model,
                component=component,
            )

    def delete_components(
        self,
        *,
        machine_id: UUID,
        component_ids: Sequence[UUID],
    ) -> None:
        unique_ids = list(
            dict.fromkeys(
                component_ids
            )
        )

        if not unique_ids:
            return

        try:
            self._session.execute(
                delete(
                    SoftwareComponentModel
                ).where(
                    SoftwareComponentModel.machine_id
                    == machine_id,
                    SoftwareComponentModel.id.in_(
                        unique_ids
                    ),
                )
            )

        except SQLAlchemyError as error:
            raise AssetInventoryRepositoryError(
                "Unable to delete disappeared "
                "software components"
            ) from error

        for component_id in unique_ids:
            self._component_models.pop(
                component_id,
                None,
            )

    @staticmethod
    def _to_organization(
        model: OrganizationModel,
    ) -> Organization:
        return Organization(
            id=model.id,
            name=model.name,
            is_active=model.is_active,
            created_at=model.created_at,
        )

    @staticmethod
    def _to_machine(
        model: MachineModel,
    ) -> Machine:
        return Machine(
            id=model.id,
            organization_id=(
                model.organization_id
            ),
            machine_uid=model.machine_uid,
            hostname=model.hostname,
            os_name=model.os_name,
            os_version=model.os_version,
            architecture=model.architecture,
            last_inventory_at=(
                model.last_inventory_at
            ),
            created_at=model.created_at,
            updated_at=model.updated_at,
        )

    @staticmethod
    def _to_inventory_state(
        model: MachineInventoryStateModel,
    ) -> MachineInventoryState:
        return MachineInventoryState(
            machine_id=model.machine_id,
            inventory_id=model.inventory_id,
            schema_version=model.schema_version,
            collected_at=model.collected_at,
            imported_at=model.imported_at,
            component_count=(
                model.component_count
            ),
        )

    @staticmethod
    def _to_component(
        model: SoftwareComponentModel,
    ) -> SoftwareComponent:
        return SoftwareComponent(
            id=model.id,
            machine_id=model.machine_id,
            component_type=model.component_type,
            name=model.name,
            normalized_name=(
                model.normalized_name
            ),
            version=model.version,
            vendor=model.vendor,
            normalized_vendor=(
                model.normalized_vendor
            ),
            ecosystem=model.ecosystem,
            external_id=model.external_id,
            scope=model.scope,
            detected_by=model.detected_by,
            created_at=model.created_at,
            updated_at=model.updated_at,
        )

    @staticmethod
    def _component_model(
        component: SoftwareComponent,
    ) -> SoftwareComponentModel:
        return SoftwareComponentModel(
            id=component.id,
            machine_id=component.machine_id,
            component_type=(
                component.component_type
            ),
            name=component.name,
            normalized_name=(
                component.normalized_name
            ),
            version=component.version,
            vendor=component.vendor,
            normalized_vendor=(
                component.normalized_vendor
            ),
            ecosystem=component.ecosystem,
            external_id=component.external_id,
            scope=component.scope,
            detected_by=component.detected_by,
            created_at=component.created_at,
            updated_at=component.updated_at,
        )

    @staticmethod
    def _apply_component(
        *,
        model: SoftwareComponentModel,
        component: SoftwareComponent,
    ) -> None:
        model.component_type = (
            component.component_type
        )
        model.name = component.name
        model.normalized_name = (
            component.normalized_name
        )
        model.version = component.version
        model.vendor = component.vendor
        model.normalized_vendor = (
            component.normalized_vendor
        )
        model.ecosystem = component.ecosystem
        model.external_id = (
            component.external_id
        )
        model.scope = component.scope
        model.detected_by = (
            component.detected_by
        )
        model.updated_at = (
            component.updated_at
        )