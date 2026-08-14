from __future__ import annotations

from collections.abc import Iterable
from typing import Protocol, runtime_checkable
from uuid import UUID

from domain.machine import Machine
from domain.machine_inventory_state import MachineInventoryState
from domain.organization import Organization
from domain.software_component import SoftwareComponent


class AssetInventoryRepositoryError(RuntimeError):
    """Erreur générique exposée par le repository d'inventaire."""


class AssetInventoryConflictError(
    AssetInventoryRepositoryError
):
    """Signale un conflit d'identité ou de concurrence."""


@runtime_checkable
class AssetInventoryRepository(Protocol):
    """
    Port de persistance nécessaire à l'import atomique inventory/v1.

    Les détails SQLAlchemy/PostgreSQL restent dans infrastructure.
    """

    def find_organization_by_id(
        self,
        organization_id: UUID,
    ) -> Organization | None:
        ...

    def find_machine_for_inventory_update(
        self,
        organization_id: UUID,
        machine_uid: UUID,
    ) -> Machine | None:
        """
        Retourne la machine ciblée par l'inventaire.

        L'implémentation doit sérialiser les écritures concurrentes
        visant une machine déjà existante afin que les contrôles
        d'idempotence et de stale inventory restent atomiques.
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
        Charge les composants courants de la machine.

        L'implémentation doit utiliser une seule requête logique,
        et non une requête par composant.
        """
        ...

    def add_components(
        self,
        components: Iterable[SoftwareComponent],
    ) -> int:
        ...

    def update_components(
        self,
        components: Iterable[SoftwareComponent],
    ) -> int:
        ...

    def delete_components_by_ids(
        self,
        machine_id: UUID,
        component_ids: Iterable[UUID],
    ) -> int:
        """
        Supprime uniquement des composants de machine_id.

        Le filtre machine_id est volontaire : une erreur applicative
        ne doit jamais permettre de supprimer un composant appartenant
        à une autre machine.
        """
        ...