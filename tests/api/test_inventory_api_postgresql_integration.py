from __future__ import annotations

import os
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from dotenv import load_dotenv
from fastapi.testclient import TestClient
from sqlalchemy import (
    Engine,
    create_engine,
    delete,
    event,
    func,
    select,
)
from sqlalchemy.engine import Connection
from sqlalchemy.orm import (
    Session,
    SessionTransaction,
    sessionmaker,
)

from application.security.machine_api_key_authenticator import (
    MachineApiCredential,
    MachineApiKeyAuthenticator,
)
from application.services.import_machine_inventory_service import (
    ImportMachineInventoryService,
)
from infrastructure.api.app import create_app
from infrastructure.persistence.models.assets import (
    MachineModel,
    OrganizationModel,
    SoftwareComponentModel,
)
from infrastructure.persistence.sqlalchemy.asset_inventory_unit_of_work import (
    SqlAlchemyAssetInventoryUnitOfWork,
)
from infrastructure.persistence.sqlalchemy.session import (
    create_session_factory,
)
from sqlalchemy import text
from sqlalchemy.exc import ProgrammingError


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


class OwnerSession(Session):
    pass


@event.listens_for(
    OwnerSession,
    "after_begin",
)
def _set_owner_role(
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
def owner_session_factory(
) -> Iterator[sessionmaker[Session]]:
    database_url = os.environ.get(
        "MIGRATION_DATABASE_URL"
    )

    if not database_url:
        raise RuntimeError(
            "MIGRATION_DATABASE_URL "
            "is not defined"
        )

    engine = create_engine(
        database_url,
        pool_pre_ping=True,
        future=True,
    )

    factory: sessionmaker[Session] = (
        sessionmaker(
            bind=engine,
            class_=OwnerSession,
            autoflush=False,
            expire_on_commit=False,
        )
    )

    try:
        yield factory
    finally:
        engine.dispose()


@pytest.fixture
def organization_id(
    owner_session_factory: (
        sessionmaker[Session]
    ),
) -> Iterator[UUID]:
    organization_id = uuid4()

    with owner_session_factory() as session:
        session.add(
            OrganizationModel(
                id=organization_id,
                name=(
                    "HTTP Inventory Integration "
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
        with owner_session_factory() as session:
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


@pytest.fixture
def asset_engine() -> Iterator[Engine]:
    database_url = os.environ.get(
        "ASSET_DATABASE_URL"
    )

    if not database_url:
        raise RuntimeError(
            "ASSET_DATABASE_URL "
            "is not defined"
        )

    engine = create_engine(
        database_url,
        pool_pre_ping=True,
        future=True,
    )

    try:
        yield engine
    finally:
        engine.dispose()


def _payload(
    *,
    machine_uid: UUID,
    inventory_id: UUID,
) -> dict:
    return {
        "schema_version": "inventory/v1",
        "inventory_id": str(
            inventory_id
        ),
        "collected_at": NOW.isoformat(),
        "agent": {
            "name": "tip-windows-agent",
            "version": "0.1.0",
        },
        "machine": {
            "machine_uid": str(
                machine_uid
            ),
            "hostname": "HTTP-TEST-PC",
            "os_name": "Windows 11 Pro",
            "os_version": "25H2",
            "architecture": "x86_64",
        },
        "components": [
            {
                "component_type": "application",
                "name": "7-Zip",
                "version": "24.09",
                "vendor": "Igor Pavlov",
                "external_id": (
                    "HKLM64\\test\\7zip"
                ),
                "detected_by": (
                    "windows_registry_uninstall"
                ),
            },
            {
                "component_type": "application",
                "name": "GitHub CLI",
                "version": "2.97.0",
                "vendor": "GitHub, Inc.",
                "external_id": (
                    "HKLM64\\test\\gh"
                ),
                "detected_by": (
                    "windows_registry_uninstall"
                ),
            },
        ],
    }


def test_http_inventory_import_uses_runtime_role_and_is_idempotent(
    asset_engine: Engine,
    owner_session_factory: (
        sessionmaker[Session]
    ),
    organization_id: UUID,
) -> None:
    api_key = (
        "integration-machine-api-key"
    )

    machine_uid = uuid4()
    inventory_id = uuid4()

    authenticator = (
        MachineApiKeyAuthenticator(
            [
                MachineApiCredential(
                    key_sha256=(
                        MachineApiKeyAuthenticator
                        .hash_api_key(
                            api_key
                        )
                    ),
                    organization_id=(
                        organization_id
                    ),
                    machine_uid=(
                        machine_uid
                    ),
                )
            ]
        )
    )

    asset_session_factory = (
        create_session_factory(
            asset_engine
        )
    )

    service = ImportMachineInventoryService(
        unit_of_work=(
            SqlAlchemyAssetInventoryUnitOfWork(
                asset_session_factory
            )
        )
    )

    app = create_app(
        import_service=service,
        authenticator=authenticator,
    )

    client = TestClient(app)

    payload = _payload(
        machine_uid=machine_uid,
        inventory_id=inventory_id,
    )

    first_response = client.post(
        "/api/v1/inventories",
        headers={
            "Authorization": (
                f"Bearer {api_key}"
            )
        },
        json=payload,
    )

    assert (
        first_response.status_code
        == 200
    )

    first_body = first_response.json()

    assert (
        first_body["status"]
        == "imported"
    )

    assert (
        first_body["machine_created"]
        is True
    )

    assert (
        first_body[
            "inserted_components"
        ]
        == 2
    )

    with owner_session_factory() as session:
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

        count = session.scalar(
            select(
                func.count(
                    SoftwareComponentModel.id
                )
            ).where(
                SoftwareComponentModel.machine_id
                == machine.id
            )
        )

        assert int(
            count or 0
        ) == 2

    second_response = client.post(
        "/api/v1/inventories",
        headers={
            "Authorization": (
                f"Bearer {api_key}"
            )
        },
        json=payload,
    )

    assert (
        second_response.status_code
        == 200
    )

    second_body = (
        second_response.json()
    )

    assert (
        second_body["status"]
        == "idempotent"
    )

    assert (
        second_body[
            "inserted_components"
        ]
        == 0
    )

    assert (
        second_body[
            "updated_components"
        ]
        == 0
    )

    assert (
        second_body[
            "deleted_components"
        ]
        == 0
    )
    
def test_asset_runtime_role_cannot_read_user_accounts(
    asset_engine: Engine,
) -> None:
    with pytest.raises(
        ProgrammingError
    ):
        with asset_engine.connect() as connection:
            connection.execute(
                text(
                    "SELECT id "
                    "FROM threat_intel.user_account "
                    "LIMIT 1"
                )
            )