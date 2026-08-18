from __future__ import annotations

import os
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from dotenv import load_dotenv
from sqlalchemy import (
    create_engine,
    delete,
    event,
)
from sqlalchemy.engine import Connection
from sqlalchemy.orm import (
    Session,
    SessionTransaction,
    sessionmaker,
)

from infrastructure.bootstrap.machine_vulnerability_processing import (
    build_process_machine_vulnerabilities_service,
)
from infrastructure.notifications.fake_notification_adapter import (
    FakeNotificationAdapter,
)
from infrastructure.persistence.models.assets import (
    MachineModel,
    OrganizationModel,
    SoftwareComponentModel,
)


PROJECT_ROOT = (
    Path(__file__).resolve().parents[2]
)

load_dotenv(
    dotenv_path=PROJECT_ROOT / ".env",
    override=False,
)

pytestmark = pytest.mark.integration


NOW = datetime(
    2026,
    8,
    18,
    15,
    0,
    tzinfo=UTC,
)


class OwnerSession(
    Session
):
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
def session_factory(
) -> Iterator[
    sessionmaker[Session]
]:
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

    factory: sessionmaker[
        Session
    ] = sessionmaker(
        bind=engine,
        class_=OwnerSession,
        autoflush=False,
        expire_on_commit=False,
    )

    try:
        yield factory

    finally:
        engine.dispose()


@pytest.fixture
def machine_seed(
    session_factory: (
        sessionmaker[Session]
    ),
) -> Iterator[
    tuple[
        UUID,
        UUID,
    ]
]:
    organization_id = uuid4()
    machine_id = uuid4()

    unique_suffix = (
        uuid4().hex
    )

    with session_factory() as session:
        session.add(
            OrganizationModel(
                id=organization_id,
                name=(
                    "process-machine-e2e-"
                    f"{unique_suffix}"
                ),
                is_active=True,
                created_at=NOW,
            )
        )

        session.flush()

        session.add(
            MachineModel(
                id=machine_id,
                organization_id=(
                    organization_id
                ),
                machine_uid=uuid4(),
                hostname=(
                    "PROCESS-E2E"
                ),
                os_name=(
                    "Windows 11 Pro"
                ),
                os_version="25H2",
                architecture="x86_64",
                last_inventory_at=NOW,
                created_at=NOW,
                updated_at=NOW,
            )
        )

        session.flush()

        # Application volontairement fictive :
        # ne doit correspondre à aucun produit CISA.
        session.add(
            SoftwareComponentModel(
                id=uuid4(),
                machine_id=machine_id,
                component_type=(
                    "application"
                ),
                name=(
                    "TIP Integration "
                    f"Application {unique_suffix}"
                ),
                normalized_name=(
                    "tip integration "
                    f"application {unique_suffix}"
                ),
                version="1.0.0",
                vendor=(
                    "TIP Integration Vendor "
                    f"{unique_suffix}"
                ),
                normalized_vendor=(
                    "tip integration vendor "
                    f"{unique_suffix}"
                ),
                ecosystem=None,
                external_id=(
                    "registry-e2e-"
                    f"{unique_suffix}"
                ),
                scope=None,
                detected_by=(
                    "windows_registry_uninstall"
                ),
                created_at=NOW,
                updated_at=NOW,
            )
        )

        # Package PyPI fictif :
        # ne doit correspondre à aucun advisory.
        session.add(
            SoftwareComponentModel(
                id=uuid4(),
                machine_id=machine_id,
                component_type="package",
                name=(
                    "tip-integration-"
                    f"{unique_suffix}"
                ),
                normalized_name=(
                    "tip-integration-"
                    f"{unique_suffix}"
                ),
                version="1.0.0",
                vendor=None,
                normalized_vendor=None,
                ecosystem="pypi",
                external_id=None,
                scope="global",
                detected_by=(
                    "pip_global"
                ),
                created_at=NOW,
                updated_at=NOW,
            )
        )

        session.commit()

    try:
        yield (
            organization_id,
            machine_id,
        )

    finally:
        with session_factory() as session:
            # machine -> component -> exposure
            # est déjà couvert par ON DELETE CASCADE.
            session.execute(
                delete(
                    MachineModel
                ).where(
                    MachineModel.id
                    == machine_id,
                    MachineModel.organization_id
                    == organization_id,
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


def test_real_machine_vulnerability_pipeline_runs_without_false_positive(
    session_factory: (
        sessionmaker[Session]
    ),
    machine_seed: tuple[
        UUID,
        UUID,
    ],
) -> None:
    (
        organization_id,
        machine_id,
    ) = machine_seed

    notification_adapter = (
        FakeNotificationAdapter()
    )

    service = (
        build_process_machine_vulnerabilities_service(
            session_factory=(
                session_factory
            ),
            notification_port=(
                notification_adapter
            ),
        )
    )

    result = service.process(
        organization_id=organization_id,
        machine_id=machine_id,
        evaluated_at=NOW,
    )

    assert (
        result.organization_id
        == organization_id
    )

    assert (
        result.machine_id
        == machine_id
    )

    assert (
        result.component_count
        == 2
    )

    assert (
        result.application_count
        == 1
    )

    assert (
        result.package_count
        == 1
    )

    # Les deux composants sont fictifs :
    # aucun matching agressif/fuzzy ne doit créer
    # une exposition.
    assert (
        result.before_exposure_count
        == 0
    )

    assert (
        result.after_exposure_count
        == 0
    )

    assert (
        result.new_exposure_count
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

    assert (
        notification_adapter
        .attempted_notifications
        == []
    )

    assert (
        notification_adapter
        .sent_notifications
        == []
    )