from __future__ import annotations

import os
from collections.abc import Iterator
from datetime import (
    UTC,
    datetime,
)
from pathlib import Path
from uuid import (
    UUID,
    uuid4,
)

import pytest
from dotenv import load_dotenv
from sqlalchemy import (
    create_engine,
    delete,
    event,
)
from sqlalchemy.engine import (
    Connection,
)
from sqlalchemy.orm import (
    Session,
    SessionTransaction,
    sessionmaker,
)

from infrastructure.persistence.models.assets import (
    MachineModel,
    OrganizationModel,
    SoftwareComponentModel,
    VulnerabilityExposureModel,
)
from infrastructure.persistence.models.canonical import (
    CanonicalVulnerabilityModel,
)
from infrastructure.persistence.sqlalchemy.readers.threat_intelligence_reprocessing_target_repository import (
    SqlAlchemyThreatIntelligenceReprocessingTargetRepository,
)


PROJECT_ROOT = (
    Path(__file__)
    .resolve()
    .parents[2]
)

load_dotenv(
    dotenv_path=PROJECT_ROOT / ".env",
    override=False,
)


pytestmark = pytest.mark.integration


NOW = datetime(
    2026,
    8,
    23,
    21,
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
def owner_session_factory(
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


class Seed:
    def __init__(
        self,
        *,
        active_organization_id: UUID,
        inactive_organization_id: UUID,
        application_machine_id: UUID,
        package_machine_id: UUID,
        empty_machine_id: UUID,
        inactive_machine_id: UUID,
        canonical_vulnerability_id: UUID,
    ) -> None:
        self.active_organization_id = (
            active_organization_id
        )

        self.inactive_organization_id = (
            inactive_organization_id
        )

        self.application_machine_id = (
            application_machine_id
        )

        self.package_machine_id = (
            package_machine_id
        )

        self.empty_machine_id = (
            empty_machine_id
        )

        self.inactive_machine_id = (
            inactive_machine_id
        )

        self.canonical_vulnerability_id = (
            canonical_vulnerability_id
        )


@pytest.fixture
def seed(
    owner_session_factory: (
        sessionmaker[Session]
    ),
) -> Iterator[
    Seed
]:
    active_organization_id = uuid4()
    inactive_organization_id = uuid4()

    application_machine_id = uuid4()
    package_machine_id = uuid4()
    empty_machine_id = uuid4()
    inactive_machine_id = uuid4()

    application_component_id = uuid4()
    package_component_id = uuid4()
    inactive_application_id = uuid4()
    inactive_package_id = uuid4()

    canonical_vulnerability_id = (
        uuid4()
    )

    package_exposure_id = uuid4()
    inactive_exposure_id = uuid4()

    with (
        owner_session_factory()
        as session
    ):
        session.add_all(
            [
                OrganizationModel(
                    id=(
                        active_organization_id
                    ),
                    name=(
                        "scheduler-active-"
                        + uuid4().hex
                    ),
                    is_active=True,
                    created_at=NOW,
                ),
                OrganizationModel(
                    id=(
                        inactive_organization_id
                    ),
                    name=(
                        "scheduler-inactive-"
                        + uuid4().hex
                    ),
                    is_active=False,
                    created_at=NOW,
                ),
            ]
        )

        session.flush()

        session.add_all(
            [
                MachineModel(
                    id=(
                        application_machine_id
                    ),
                    organization_id=(
                        active_organization_id
                    ),
                    machine_uid=uuid4(),
                    hostname=(
                        "SCHEDULER-APP"
                    ),
                    os_name="Windows 11",
                    os_version="25H2",
                    architecture="x86_64",
                    last_inventory_at=NOW,
                    created_at=NOW,
                    updated_at=NOW,
                ),
                MachineModel(
                    id=(
                        package_machine_id
                    ),
                    organization_id=(
                        active_organization_id
                    ),
                    machine_uid=uuid4(),
                    hostname=(
                        "SCHEDULER-PACKAGE"
                    ),
                    os_name="Windows 11",
                    os_version="25H2",
                    architecture="x86_64",
                    last_inventory_at=NOW,
                    created_at=NOW,
                    updated_at=NOW,
                ),
                MachineModel(
                    id=empty_machine_id,
                    organization_id=(
                        active_organization_id
                    ),
                    machine_uid=uuid4(),
                    hostname=(
                        "SCHEDULER-EMPTY"
                    ),
                    os_name="Windows 11",
                    os_version="25H2",
                    architecture="x86_64",
                    last_inventory_at=NOW,
                    created_at=NOW,
                    updated_at=NOW,
                ),
                MachineModel(
                    id=inactive_machine_id,
                    organization_id=(
                        inactive_organization_id
                    ),
                    machine_uid=uuid4(),
                    hostname=(
                        "SCHEDULER-INACTIVE"
                    ),
                    os_name="Windows 11",
                    os_version="25H2",
                    architecture="x86_64",
                    last_inventory_at=NOW,
                    created_at=NOW,
                    updated_at=NOW,
                ),
            ]
        )

        session.flush()

        session.add_all(
            [
                SoftwareComponentModel(
                    id=(
                        application_component_id
                    ),
                    machine_id=(
                        application_machine_id
                    ),
                    component_type=(
                        "application"
                    ),
                    name=(
                        "Scheduler Application"
                    ),
                    normalized_name=(
                        "scheduler application"
                    ),
                    version="1.0",
                    vendor="Example Vendor",
                    normalized_vendor=(
                        "example vendor"
                    ),
                    ecosystem=None,
                    external_id=(
                        "scheduler-app-id"
                    ),
                    scope=None,
                    detected_by=(
                        "windows_registry_uninstall"
                    ),
                    created_at=NOW,
                    updated_at=NOW,
                ),
                SoftwareComponentModel(
                    id=package_component_id,
                    machine_id=(
                        package_machine_id
                    ),
                    component_type="package",
                    name="scheduler-package",
                    normalized_name=(
                        "scheduler-package"
                    ),
                    version="1.0.0",
                    vendor=None,
                    normalized_vendor=None,
                    ecosystem="npm",
                    external_id=None,
                    scope="global",
                    detected_by="npm_global",
                    created_at=NOW,
                    updated_at=NOW,
                ),
                SoftwareComponentModel(
                    id=(
                        inactive_application_id
                    ),
                    machine_id=(
                        inactive_machine_id
                    ),
                    component_type=(
                        "application"
                    ),
                    name=(
                        "Inactive Application"
                    ),
                    normalized_name=(
                        "inactive application"
                    ),
                    version="1.0",
                    vendor="Example Vendor",
                    normalized_vendor=(
                        "example vendor"
                    ),
                    ecosystem=None,
                    external_id=(
                        "inactive-app-id"
                    ),
                    scope=None,
                    detected_by=(
                        "windows_registry_uninstall"
                    ),
                    created_at=NOW,
                    updated_at=NOW,
                ),
                SoftwareComponentModel(
                    id=inactive_package_id,
                    machine_id=(
                        inactive_machine_id
                    ),
                    component_type="package",
                    name="inactive-package",
                    normalized_name=(
                        "inactive-package"
                    ),
                    version="1.0.0",
                    vendor=None,
                    normalized_vendor=None,
                    ecosystem="npm",
                    external_id=None,
                    scope="global",
                    detected_by="npm_global",
                    created_at=NOW,
                    updated_at=NOW,
                ),
            ]
        )

        session.add(
            CanonicalVulnerabilityModel(
                id=(
                    canonical_vulnerability_id
                ),
                status="active",
                correlation_version=1,
                merged_into_id=None,
                created_at=NOW,
                updated_at=NOW,
            )
        )

        session.flush()

        session.add_all(
            [
                VulnerabilityExposureModel(
                    id=package_exposure_id,
                    software_component_id=(
                        package_component_id
                    ),
                    canonical_vulnerability_id=(
                        canonical_vulnerability_id
                    ),
                    applicability_status=(
                        "confirmed"
                    ),
                    match_rule=(
                        "scheduler_test"
                    ),
                    match_version="1",
                    severity="HIGH",
                    priority="HIGH",
                    is_kev=False,
                    first_detected_at=NOW,
                    last_evaluated_at=NOW,
                ),
                VulnerabilityExposureModel(
                    id=inactive_exposure_id,
                    software_component_id=(
                        inactive_package_id
                    ),
                    canonical_vulnerability_id=(
                        canonical_vulnerability_id
                    ),
                    applicability_status=(
                        "confirmed"
                    ),
                    match_rule=(
                        "scheduler_test"
                    ),
                    match_version="1",
                    severity="HIGH",
                    priority="HIGH",
                    is_kev=False,
                    first_detected_at=NOW,
                    last_evaluated_at=NOW,
                ),
            ]
        )

        session.commit()

    seeded = Seed(
        active_organization_id=(
            active_organization_id
        ),
        inactive_organization_id=(
            inactive_organization_id
        ),
        application_machine_id=(
            application_machine_id
        ),
        package_machine_id=(
            package_machine_id
        ),
        empty_machine_id=empty_machine_id,
        inactive_machine_id=(
            inactive_machine_id
        ),
        canonical_vulnerability_id=(
            canonical_vulnerability_id
        ),
    )

    try:
        yield seeded

    finally:
        with (
            owner_session_factory()
            as session
        ):
            session.execute(
                delete(
                    VulnerabilityExposureModel
                )
                .where(
                    VulnerabilityExposureModel
                    .canonical_vulnerability_id
                    == canonical_vulnerability_id
                )
            )

            session.execute(
                delete(
                    SoftwareComponentModel
                )
                .where(
                    SoftwareComponentModel
                    .machine_id.in_(
                        (
                            application_machine_id,
                            package_machine_id,
                            empty_machine_id,
                            inactive_machine_id,
                        )
                    )
                )
            )

            session.execute(
                delete(
                    MachineModel
                )
                .where(
                    MachineModel.id.in_(
                        (
                            application_machine_id,
                            package_machine_id,
                            empty_machine_id,
                            inactive_machine_id,
                        )
                    )
                )
            )

            session.execute(
                delete(
                    OrganizationModel
                )
                .where(
                    OrganizationModel.id.in_(
                        (
                            active_organization_id,
                            inactive_organization_id,
                        )
                    )
                )
            )

            session.execute(
                delete(
                    CanonicalVulnerabilityModel
                )
                .where(
                    CanonicalVulnerabilityModel.id
                    == canonical_vulnerability_id
                )
            )

            session.commit()


def _repository(
    owner_session_factory: (
        sessionmaker[Session]
    ),
):
    return (
        SqlAlchemyThreatIntelligenceReprocessingTargetRepository(
            session_factory=(
                owner_session_factory
            )
        )
    )


def test_application_targets_are_selected(
    owner_session_factory,
    seed,
):
    repository = _repository(
        owner_session_factory
    )

    targets = (
        repository
        .find_application_targets()
    )

    matching = tuple(
        target
        for target in targets
        if (
            target.organization_id
            == seed.active_organization_id
        )
    )

    assert {
        target.machine_id
        for target in matching
    } == {
        seed.application_machine_id,
    }

    assert (
        seed.inactive_machine_id
        not in {
            target.machine_id
            for target in targets
        }
    )


def test_package_targets_are_selected(
    owner_session_factory,
    seed,
):
    repository = _repository(
        owner_session_factory
    )

    targets = (
        repository
        .find_package_targets()
    )

    matching = tuple(
        target
        for target in targets
        if (
            target.organization_id
            == seed.active_organization_id
        )
    )

    assert {
        target.machine_id
        for target in matching
    } == {
        seed.package_machine_id,
    }

    assert (
        seed.inactive_machine_id
        not in {
            target.machine_id
            for target in targets
        }
    )


def test_exposure_targets_are_selected(
    owner_session_factory,
    seed,
):
    repository = _repository(
        owner_session_factory
    )

    targets = (
        repository
        .find_exposure_targets()
    )

    matching = tuple(
        target
        for target in targets
        if (
            target.organization_id
            == seed.active_organization_id
        )
    )

    assert {
        target.machine_id
        for target in matching
    } == {
        seed.package_machine_id,
    }

    assert (
        seed.application_machine_id
        not in {
            target.machine_id
            for target in matching
        }
    )

    assert (
        seed.empty_machine_id
        not in {
            target.machine_id
            for target in matching
        }
    )

    assert (
        seed.inactive_machine_id
        not in {
            target.machine_id
            for target in targets
        }
    )