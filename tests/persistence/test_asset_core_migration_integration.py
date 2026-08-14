from __future__ import annotations

import os
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from dotenv import load_dotenv
from sqlalchemy import create_engine, func, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from sqlalchemy.pool import NullPool

from infrastructure.persistence.models.assets import (
    AlertModel,
    MachineInventoryStateModel,
    MachineModel,
    OrganizationModel,
    SoftwareComponentModel,
    UserAccountModel,
    VulnerabilityExposureModel,
)
from infrastructure.persistence.models.canonical import (
    CanonicalVulnerabilityModel,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]

load_dotenv(
    dotenv_path=PROJECT_ROOT / ".env",
    override=False,
)

pytestmark = pytest.mark.integration


@pytest.fixture
def owner_session() -> Iterator[Session]:
    database_url = os.environ.get(
        "MIGRATION_DATABASE_URL"
    )

    if not database_url:
        raise RuntimeError(
            "MIGRATION_DATABASE_URL is not defined"
        )

    engine = create_engine(
        database_url,
        pool_pre_ping=True,
        poolclass=NullPool,
        future=True,
    )

    connection = engine.connect()

    connection.execute(
        text("SET ROLE threat_intel_owner")
    )
    connection.commit()

    session = Session(
        bind=connection,
        autoflush=False,
        expire_on_commit=False,
    )

    try:
        yield session
    finally:
        session.rollback()
        session.close()

        connection.execute(
            text("RESET ROLE")
        )
        connection.commit()

        connection.close()
        engine.dispose()


def _organization(
    session: Session,
) -> OrganizationModel:
    organization = OrganizationModel(
        id=uuid4(),
        name=f"org-{uuid4().hex}",
        created_at=datetime.now(UTC),
    )

    session.add(organization)
    session.flush()

    return organization


def _user(
    session: Session,
    organization_id: UUID,
    *,
    email: str | None = None,
) -> UserAccountModel:
    user = UserAccountModel(
        id=uuid4(),
        organization_id=organization_id,
        email=(
            email
            or f"{uuid4().hex}@example.test"
        ),
        display_name="Security Responsible",
        role="security_responsible",
        created_at=datetime.now(UTC),
    )

    session.add(user)
    session.flush()

    return user


def _machine(
    session: Session,
    organization_id: UUID,
    *,
    machine_uid: UUID | None = None,
) -> MachineModel:
    now = datetime.now(UTC)

    machine = MachineModel(
        id=uuid4(),
        organization_id=organization_id,
        machine_uid=machine_uid or uuid4(),
        hostname=f"host-{uuid4().hex[:12]}",
        os_name="Windows",
        os_version="11",
        architecture="x86_64",
        last_inventory_at=None,
        created_at=now,
        updated_at=now,
    )

    session.add(machine)
    session.flush()

    return machine


def _inventory_state(
    session: Session,
    machine_id: UUID,
    *,
    inventory_id: UUID | None = None,
) -> MachineInventoryStateModel:
    now = datetime.now(UTC)

    state = MachineInventoryStateModel(
        machine_id=machine_id,
        inventory_id=inventory_id or uuid4(),
        schema_version="inventory/v1",
        collected_at=now,
        imported_at=now,
        component_count=0,
    )

    session.add(state)
    session.flush()

    return state


def _application(
    session: Session,
    machine_id: UUID,
    *,
    external_id: str | None = None,
) -> SoftwareComponentModel:
    now = datetime.now(UTC)

    component = SoftwareComponentModel(
        id=uuid4(),
        machine_id=machine_id,
        component_type="application",
        name="7-Zip",
        normalized_name=None,
        version="24.09",
        vendor="Igor Pavlov",
        normalized_vendor=None,
        ecosystem=None,
        external_id=(
            external_id
            or f"registry-{uuid4()}"
        ),
        scope=None,
        detected_by="windows_registry_uninstall",
        created_at=now,
        updated_at=now,
    )

    session.add(component)
    session.flush()

    return component


def _package(
    session: Session,
    machine_id: UUID,
    *,
    name: str,
    version: str,
) -> SoftwareComponentModel:
    now = datetime.now(UTC)

    component = SoftwareComponentModel(
        id=uuid4(),
        machine_id=machine_id,
        component_type="package",
        name=name,
        normalized_name=None,
        version=version,
        vendor=None,
        normalized_vendor=None,
        ecosystem="pypi",
        external_id=None,
        scope="global",
        detected_by="pip_global",
        created_at=now,
        updated_at=now,
    )

    session.add(component)
    session.flush()

    return component


def _canonical_vulnerability(
    session: Session,
) -> CanonicalVulnerabilityModel:
    now = datetime.now(UTC)

    vulnerability = CanonicalVulnerabilityModel(
        id=uuid4(),
        created_at=now,
        updated_at=now,
    )

    session.add(vulnerability)
    session.flush()

    return vulnerability


def _exposure(
    session: Session,
    component_id: UUID,
    vulnerability_id: UUID,
) -> VulnerabilityExposureModel:
    now = datetime.now(UTC)

    exposure = VulnerabilityExposureModel(
        id=uuid4(),
        software_component_id=component_id,
        canonical_vulnerability_id=(
            vulnerability_id
        ),
        applicability_status="confirmed",
        match_rule="test_exact_match_v1",
        match_version="24.09",
        severity="HIGH",
        priority=None,
        is_kev=False,
        first_detected_at=now,
        last_evaluated_at=now,
    )

    session.add(exposure)
    session.flush()

    return exposure


def _alert(
    session: Session,
    *,
    organization_id: UUID,
    machine_id: UUID,
    vulnerability_id: UUID,
    recipient_user_id: UUID,
    exposure_id: UUID | None = None,
) -> AlertModel:
    alert = AlertModel(
        id=uuid4(),
        organization_id=organization_id,
        machine_id=machine_id,
        vulnerability_exposure_id=exposure_id,
        canonical_vulnerability_id=(
            vulnerability_id
        ),
        alert_type=(
            "new_confirmed_critical_exposure"
        ),
        recipient_user_id=recipient_user_id,
        status="pending",
        deduplication_key=f"test:{uuid4()}",
        created_at=datetime.now(UTC),
        sent_at=None,
    )

    session.add(alert)
    session.flush()

    return alert


def _count_by_id(
    session: Session,
    model: type,
    object_id: UUID,
) -> int:
    count = session.scalar(
        select(func.count())
        .select_from(model)
        .where(model.id == object_id)
    )

    assert count is not None

    return count


def test_machine_uid_is_unique_per_organization(
    owner_session: Session,
) -> None:
    organization_a = _organization(
        owner_session
    )
    organization_b = _organization(
        owner_session
    )

    shared_uid = uuid4()

    _machine(
        owner_session,
        organization_a.id,
        machine_uid=shared_uid,
    )

    # Même machine_uid dans un autre tenant :
    # autorisé.
    _machine(
        owner_session,
        organization_b.id,
        machine_uid=shared_uid,
    )

    # Même machine_uid dans le même tenant :
    # interdit.
    with pytest.raises(IntegrityError):
        _machine(
            owner_session,
            organization_a.id,
            machine_uid=shared_uid,
        )


def test_user_email_is_unique_per_organization(
    owner_session: Session,
) -> None:
    organization_a = _organization(
        owner_session
    )
    organization_b = _organization(
        owner_session
    )

    email = "security@example.test"

    _user(
        owner_session,
        organization_a.id,
        email=email,
    )

    # Même email dans une autre organisation :
    # autorisé.
    _user(
        owner_session,
        organization_b.id,
        email=email,
    )

    with pytest.raises(IntegrityError):
        _user(
            owner_session,
            organization_a.id,
            email=email,
        )


def test_inventory_id_is_not_global_identity(
    owner_session: Session,
) -> None:
    organization = _organization(
        owner_session
    )

    machine_a = _machine(
        owner_session,
        organization.id,
    )
    machine_b = _machine(
        owner_session,
        organization.id,
    )

    shared_inventory_id = uuid4()

    _inventory_state(
        owner_session,
        machine_a.id,
        inventory_id=shared_inventory_id,
    )

    _inventory_state(
        owner_session,
        machine_b.id,
        inventory_id=shared_inventory_id,
    )

    count = owner_session.scalar(
        select(func.count())
        .select_from(
            MachineInventoryStateModel
        )
        .where(
            MachineInventoryStateModel.inventory_id
            == shared_inventory_id
        )
    )

    assert count == 2


def test_application_identity_is_unique_per_machine(
    owner_session: Session,
) -> None:
    organization = _organization(
        owner_session
    )
    machine = _machine(
        owner_session,
        organization.id,
    )

    external_id = (
        "HKLM64\\SOFTWARE\\"
        "Microsoft\\Windows\\"
        "CurrentVersion\\Uninstall\\7-Zip"
    )

    _application(
        owner_session,
        machine.id,
        external_id=external_id,
    )

    with pytest.raises(IntegrityError):
        _application(
            owner_session,
            machine.id,
            external_id=external_id,
        )


def test_package_identity_excludes_version(
    owner_session: Session,
) -> None:
    organization = _organization(
        owner_session
    )
    machine = _machine(
        owner_session,
        organization.id,
    )

    _package(
        owner_session,
        machine.id,
        name="requests",
        version="2.31.0",
    )

    # Une nouvelle version est un UPDATE futur,
    # pas un deuxième composant.
    with pytest.raises(IntegrityError):
        _package(
            owner_session,
            machine.id,
            name="requests",
            version="2.32.0",
        )


def test_exposure_requires_existing_canonical_vulnerability(
    owner_session: Session,
) -> None:
    organization = _organization(
        owner_session
    )
    machine = _machine(
        owner_session,
        organization.id,
    )
    component = _application(
        owner_session,
        machine.id,
    )

    with pytest.raises(IntegrityError):
        _exposure(
            owner_session,
            component.id,
            uuid4(),
        )


def test_alert_rejects_cross_tenant_machine(
    owner_session: Session,
) -> None:
    organization_a = _organization(
        owner_session
    )
    organization_b = _organization(
        owner_session
    )

    recipient = _user(
        owner_session,
        organization_a.id,
    )

    foreign_machine = _machine(
        owner_session,
        organization_b.id,
    )

    vulnerability = (
        _canonical_vulnerability(
            owner_session
        )
    )

    with pytest.raises(IntegrityError):
        _alert(
            owner_session,
            organization_id=organization_a.id,
            machine_id=foreign_machine.id,
            vulnerability_id=vulnerability.id,
            recipient_user_id=recipient.id,
        )


def test_alert_rejects_cross_tenant_recipient(
    owner_session: Session,
) -> None:
    organization_a = _organization(
        owner_session
    )
    organization_b = _organization(
        owner_session
    )

    machine = _machine(
        owner_session,
        organization_a.id,
    )

    foreign_recipient = _user(
        owner_session,
        organization_b.id,
    )

    vulnerability = (
        _canonical_vulnerability(
            owner_session
        )
    )

    with pytest.raises(IntegrityError):
        _alert(
            owner_session,
            organization_id=organization_a.id,
            machine_id=machine.id,
            vulnerability_id=vulnerability.id,
            recipient_user_id=(
                foreign_recipient.id
            ),
        )


def test_machine_delete_cascades_inventory_components_and_exposures(
    owner_session: Session,
) -> None:
    organization = _organization(
        owner_session
    )
    machine = _machine(
        owner_session,
        organization.id,
    )

    state = _inventory_state(
        owner_session,
        machine.id,
    )

    component = _application(
        owner_session,
        machine.id,
    )

    vulnerability = (
        _canonical_vulnerability(
            owner_session
        )
    )

    exposure = _exposure(
        owner_session,
        component.id,
        vulnerability.id,
    )

    machine_id = machine.id
    component_id = component.id
    exposure_id = exposure.id
    vulnerability_id = vulnerability.id

    owner_session.delete(machine)
    owner_session.flush()

    state_count = owner_session.scalar(
        select(func.count())
        .select_from(
            MachineInventoryStateModel
        )
        .where(
            MachineInventoryStateModel.machine_id
            == machine_id
        )
    )

    assert state_count == 0

    assert _count_by_id(
        owner_session,
        SoftwareComponentModel,
        component_id,
    ) == 0

    assert _count_by_id(
        owner_session,
        VulnerabilityExposureModel,
        exposure_id,
    ) == 0

    # La vulnérabilité canonique appartient à la
    # Threat Intelligence layer et doit survivre.
    assert _count_by_id(
        owner_session,
        CanonicalVulnerabilityModel,
        vulnerability_id,
    ) == 1

    assert state.machine_id == machine_id


def test_alert_survives_exposure_deletion(
    owner_session: Session,
) -> None:
    organization = _organization(
        owner_session
    )

    recipient = _user(
        owner_session,
        organization.id,
    )

    machine = _machine(
        owner_session,
        organization.id,
    )

    component = _application(
        owner_session,
        machine.id,
    )

    vulnerability = (
        _canonical_vulnerability(
            owner_session
        )
    )

    exposure = _exposure(
        owner_session,
        component.id,
        vulnerability.id,
    )

    alert = _alert(
        owner_session,
        organization_id=organization.id,
        machine_id=machine.id,
        vulnerability_id=vulnerability.id,
        recipient_user_id=recipient.id,
        exposure_id=exposure.id,
    )

    alert_id = alert.id

    # Disparition du logiciel :
    # component -> exposure est supprimé.
    owner_session.delete(component)
    owner_session.flush()

    # La FK alert -> exposure est ON DELETE SET NULL.
    owner_session.expire_all()

    persisted_alert = owner_session.get(
        AlertModel,
        alert_id,
    )

    assert persisted_alert is not None

    assert (
        persisted_alert.vulnerability_exposure_id
        is None
    )