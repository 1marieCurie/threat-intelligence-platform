from __future__ import annotations

from collections.abc import (
    Callable,
    Mapping,
)
from datetime import (
    UTC,
    datetime,
)
from typing import Any
from uuid import UUID

from application.models.machine_inventory_v1 import (
    MachineInventoryV1,
)
from application.services.import_machine_inventory_service import (
    ImportMachineInventoryResult,
    ImportMachineInventoryService,
)
from application.services.process_machine_vulnerabilities_service import (
    ProcessMachineVulnerabilitiesService,
)


def _utc_now() -> datetime:
    return datetime.now(
        UTC
    )


class ImportAndProcessMachineInventoryService:
    """
    Orchestre l'import d'un inventaire machine puis
    le traitement de ses vulnérabilités.

    Pipeline :

        inventory/v1
            ↓
        ImportMachineInventoryService
            ↓
        machine_id
            ↓
        ProcessMachineVulnerabilitiesService
            ↓
        expositions / severity / priority / alertes

    L'import reste la source de vérité pour le résultat
    retourné aux endpoints existants.

    Le traitement des vulnérabilités est également lancé
    lorsqu'un inventory_id est rejoué de manière
    idempotente. Cela permet de recalculer les expositions
    avec l'état Threat Intelligence courant sans dupliquer
    l'inventaire.

    Les deux services possèdent leurs propres frontières
    transactionnelles. Si le traitement des vulnérabilités
    échoue après un import réussi, l'import reste persisté.
    Un retry du même inventaire sera alors idempotent et
    relancera le traitement des vulnérabilités.
    """

    def __init__(
        self,
        *,
        import_service: (
            ImportMachineInventoryService
        ),
        vulnerability_processing_service: (
            ProcessMachineVulnerabilitiesService
        ),
        clock: Callable[
            [],
            datetime,
        ] = _utc_now,
    ) -> None:
        if import_service is None:
            raise ValueError(
                "import_service must not be None"
            )

        if (
            vulnerability_processing_service
            is None
        ):
            raise ValueError(
                "vulnerability_processing_service "
                "must not be None"
            )

        if clock is None:
            raise ValueError(
                "clock must not be None"
            )

        if not callable(
            clock
        ):
            raise TypeError(
                "clock must be callable"
            )

        self._import_service = (
            import_service
        )

        self._vulnerability_processing_service = (
            vulnerability_processing_service
        )

        self._clock = clock

    def import_inventory(
        self,
        *,
        organization_id: UUID,
        inventory_payload: (
            MachineInventoryV1
            | Mapping[
                str,
                Any,
            ]
        ),
    ) -> ImportMachineInventoryResult:
        import_result = (
            self._import_service
            .import_inventory(
                organization_id=(
                    organization_id
                ),
                inventory_payload=(
                    inventory_payload
                ),
            )
        )

        evaluated_at = (
            self._clock()
        )

        (
            self
            ._vulnerability_processing_service
            .process(
                organization_id=(
                    organization_id
                ),
                machine_id=(
                    import_result.machine_id
                ),
                evaluated_at=(
                    evaluated_at
                ),
            )
        )

        return import_result