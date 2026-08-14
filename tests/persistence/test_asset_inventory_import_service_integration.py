from __future__ import annotations

import os
from collections.abc import (
    Callable,
    Iterator,
)
from sqlalchemy.engine import Connection
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from dotenv import load_dotenv
from sqlalchemy import (
    Engine,
    create_engine,
    delete,
    event,
    select,
)
from sqlalchemy.orm import (
    Session,
    SessionTransaction,
    sessionmaker,
)

from application.services.import_machine_inventory_service import (
    ImportMachineInventoryService,
)
from infrastructure.persistence.models.assets import (
    MachineInventoryStateModel,
    MachineModel,
    OrganizationModel,
    SoftwareComponentModel,
)
from infrastructure.persistence.sqlalchemy.asset_inventory_unit_of_work import (
    SqlAlchemyAssetInventoryUnitOfWork,
)


PROJECT_ROOT = Path(
    __file__
).resolve().parents[2]

load_dotenv(
    dotenv_path=PROJECT_ROOT / ".env",
    override=False,
)

pytestmark = pytest.mark.integration


NOW = datetime(
    2026,
    8,
    14,
    16,
    0,
    tzinfo=UTC,
)


class _AssetOwnerTestSession(
    Session
):
    pass

AssetSessionFactory = Callable[
    [],
    Session,
]

@event.listens_for(
    _AssetOwnerTestSession,
    "after_begin",
)
def _set_asset_owner_role(
    session: Session,
    transaction: SessionTransaction,
    connection: Connection,
) -> None:
    del session
    del transaction

    connection.exec_driver_sql(
        "SET LOCAL ROLE threat_intel_owner"
    )

@pytest.fixture
def asset_session_factory(
) -> Iterator[
    AssetSessionFactory
]:
    database_url = os.environ.get(
        "MIGRATION_DATABASE_URL"
    )

    if not database_url:
        raise RuntimeError(
            "MIGRATION_DATABASE_URL "
            "is not defined"
        )

    engine: Engine = create_engine(
        database_url,
        pool_pre_ping=True,
        future=True,
    )

    factory = sessionmaker(
        bind=engine,
        class_=_AssetOwnerTestSession,
        autoflush=False,
        expire_on_commit=False,
    )

    try:
        yield factory
    finally:
        engine.dispose()


@pytest.fixture
def organization_id(
    asset_session_factory: (
        sessionmaker[Session]
    ),
) -> Iterator[UUID]:
    organization_id = uuid4()

    with asset_session_factory() as session:
        session.add(
            OrganizationModel(
                id=organization_id,
                name=(
                    f"asset-test-"
                    f"{uuid4().hex}"
                ),
                is_active=True,
                created_at=NOW,
            )
        )

        session.commit()

    try:
        yield organization_id

    finally:
        with asset_session_factory() as session:
            # Machine -> inventory state/components
            # utilise ON DELETE CASCADE.
            session.execute(
                delete(
                    MachineModel
                ).where(
                    MachineModel.organization_id
                    == organization_id
                )
            )

            session.execute(
                delete(
                    OrganizationModel
                ).where(
                    OrganizationModel.id
                    == organization_id
                )
            )

            session.commit()


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


def _payload(
    *,
    machine_uid: UUID,
    collected_at: datetime,
    inventory_id: UUID | None = None,
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


def test_sqlalchemy_import_persists_inventory_atomically(
    asset_session_factory: (
        sessionmaker[Session]
    ),
    organization_id: UUID,
) -> None:
    machine_uid = uuid4()

    service = ImportMachineInventoryService(
        unit_of_work=(
            SqlAlchemyAssetInventoryUnitOfWork(
                asset_session_factory
            )
        ),
        clock=lambda: NOW,
    )

    result = service.import_inventory(
        organization_id=organization_id,
        inventory_payload=_payload(
            machine_uid=machine_uid,
            collected_at=NOW,
            components=[
                _application(
                    name="7-Zip",
                    version="24.09",
                    external_id=(
                        "registry-7zip"
                    ),
                ),
                _application(
                    name="GitHub CLI",
                    version="2.97.0",
                    external_id=(
                        "registry-gh"
                    ),
                ),
            ],
        ),
    )

    assert result.status == "imported"
    assert result.machine_created is True
    assert result.component_count == 2

    with asset_session_factory() as session:
        machine = session.scalar(
            select(
                MachineModel
            ).where(
                MachineModel.organization_id
                == organization_id,
                MachineModel.machine_uid
                == machine_uid,
            )
        )

        assert machine is not None

        state = session.get(
            MachineInventoryStateModel,
            machine.id,
        )

        assert state is not None
        assert state.component_count == 2

        components = list(
            session.scalars(
                select(
                    SoftwareComponentModel
                ).where(
                    SoftwareComponentModel.machine_id
                    == machine.id
                )
            )
        )

        assert len(components) == 2

        assert {
            component.external_id
            for component in components
        } == {
            "registry-7zip",
            "registry-gh",
        }


def test_sqlalchemy_replay_is_idempotent(
    asset_session_factory: (
        sessionmaker[Session]
    ),
    organization_id: UUID,
) -> None:
    machine_uid = uuid4()
    inventory_id = uuid4()

    payload = _payload(
        machine_uid=machine_uid,
        inventory_id=inventory_id,
        collected_at=NOW,
        components=[
            _application(
                name="7-Zip",
                version="24.09",
                external_id="registry-7zip",
            )
        ],
    )

    service = ImportMachineInventoryService(
        unit_of_work=(
            SqlAlchemyAssetInventoryUnitOfWork(
                asset_session_factory
            )
        ),
        clock=lambda: NOW,
    )

    first = service.import_inventory(
        organization_id=organization_id,
        inventory_payload=payload,
    )

    second = service.import_inventory(
        organization_id=organization_id,
        inventory_payload=payload,
    )

    assert first.status == "imported"
    assert second.status == "idempotent"

    with asset_session_factory() as session:
        machine = session.scalar(
            select(
                MachineModel
            ).where(
                MachineModel.organization_id
                == organization_id,
                MachineModel.machine_uid
                == machine_uid,
            )
        )

        assert machine is not None

        components = list(
            session.scalars(
                select(
                    SoftwareComponentModel
                ).where(
                    SoftwareComponentModel.machine_id
                    == machine.id
                )
            )
        )

        assert len(components) == 1


def test_sqlalchemy_reconciliation_preserves_component_identity(
    asset_session_factory: (
        sessionmaker[Session]
    ),
    organization_id: UUID,
) -> None:
    machine_uid = uuid4()

    later = NOW + timedelta(
        minutes=10
    )

    service = ImportMachineInventoryService(
        unit_of_work=(
            SqlAlchemyAssetInventoryUnitOfWork(
                asset_session_factory
            )
        ),
        clock=lambda: later,
    )

    service.import_inventory(
        organization_id=organization_id,
        inventory_payload=_payload(
            machine_uid=machine_uid,
            collected_at=NOW,
            components=[
                _application(
                    name="7-Zip",
                    version="24.08",
                    external_id=(
                        "registry-7zip"
                    ),
                ),
                _application(
                    name="Old App",
                    version="1.0",
                    external_id=(
                        "registry-old"
                    ),
                ),
            ],
        ),
    )

    with asset_session_factory() as session:
        original = session.scalar(
            select(
                SoftwareComponentModel
            ).where(
                SoftwareComponentModel.external_id
                == "registry-7zip"
            )
        )

        assert original is not None
        original_id = original.id

    result = service.import_inventory(
        organization_id=organization_id,
        inventory_payload=_payload(
            machine_uid=machine_uid,
            collected_at=later,
            components=[
                _application(
                    name="7-Zip",
                    version="24.09",
                    external_id=(
                        "registry-7zip"
                    ),
                ),
                _application(
                    name="New App",
                    version="2.0",
                    external_id=(
                        "registry-new"
                    ),
                ),
            ],
        ),
    )

    assert result.inserted_components == 1
    assert result.updated_components == 1
    assert result.deleted_components == 1

    with asset_session_factory() as session:
        components = list(
            session.scalars(
                select(
                    SoftwareComponentModel
                )
                .join(
                    MachineModel,
                    MachineModel.id
                    == SoftwareComponentModel.machine_id,
                )
                .where(
                    MachineModel.organization_id
                    == organization_id
                )
            )
        )

        by_external_id = {
            component.external_id: component
            for component in components
        }

        assert set(
            by_external_id
        ) == {
            "registry-7zip",
            "registry-new",
        }

        assert (
            by_external_id[
                "registry-7zip"
            ].id
            == original_id
        )

        assert (
            by_external_id[
                "registry-7zip"
            ].version
            == "24.09"
        )