from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol
from uuid import UUID

from domain.machine import Machine
from domain.machine_inventory_state import (
    MachineInventoryState,
)
from domain.organization import Organization
from domain.software_component import SoftwareComponent


class AssetInventoryRepositoryError(
    RuntimeError
):
    pass


class AssetInventoryConflictError(
    AssetInventoryRepositoryError
):
    pass


class AssetInventoryRepository(Protocol):
    """
    Port de persistance de l'inventaire machine.

    Toutes les méthodes d'une même opération d'import
    utilisent la même transaction via la Unit of Work.
    """

    def find_organization_by_id(
        self,
        organization_id: UUID,
    ) -> Organization | None:
        ...

    def find_machine_for_inventory_update(
        self,
        *,
        organization_id: UUID,
        machine_uid: UUID,
    ) -> Machine | None:
        """
        Charge la machine dans le tenant demandé.

        Une implémentation SQL doit verrouiller la ligne
        existante afin de sérialiser deux imports concurrents
        de la même machine.
        """
        ...

    def add_machine(
        self,
        machine: Machine,
    ) -> None:
        ...

    def update_machine(
        self,
        machine: Machine,
    ) -> None:
        ...

    def find_inventory_state(
        self,
        machine_id: UUID,
    ) -> MachineInventoryState | None:
        ...

    def save_inventory_state(
        self,
        state: MachineInventoryState,
    ) -> None:
        ...

    def list_components(
        self,
        machine_id: UUID,
    ) -> list[SoftwareComponent]:
        """
        Charge l'inventaire logiciel courant en une
        requête logique.
        """
        ...

    def add_components(
        self,
        components: Sequence[
            SoftwareComponent
        ],
    ) -> None:
        ...

    def update_components(
        self,
        components: Sequence[
            SoftwareComponent
        ],
    ) -> None:
        ...

    def delete_components(
        self,
        *,
        machine_id: UUID,
        component_ids: Sequence[UUID],
    ) -> None:
        ...