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
from sqlalchemy.engine import Connection
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
    CanonicalVulnerabilityIdentifierModel,
    CanonicalVulnerabilityModel,
)
from infrastructure.persistence.models.ops import (
    SourceModel,
)
from infrastructure.persistence.sqlalchemy.readers.relevant_exposure_cve_reader import (
    SqlAlchemyRelevantExposureCVEReader,
)
from infrastructure.persistence.sqlalchemy.readers.scheduler_source_resolver import (
    SchedulerSourceResolutionError,
    SqlAlchemySchedulerSourceResolver,
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
    22,
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
        enabled_source_code: str,
        enabled_source_id: UUID,
        disabled_source_code: str,
        active_organization_id: UUID,
        inactive_organization_id: UUID,
        active_machine_id: UUID,
        inactive_machine_id: UUID,
        vulnerability_ids: tuple[
            UUID,
            ...,
        ],
    ) -> None:
        self.enabled_source_code = (
            enabled_source_code
        )

        self.enabled_source_id = (
            enabled_source_id
        )

        self.disabled_source_code = (
            disabled_source_code
        )

        self.active_organization_id = (
            active_organization_id
        )

        self.inactive_organization_id = (
            inactive_organization_id
        )

        self.active_machine_id = (
            active_machine_id
        )

        self.inactive_machine_id = (
            inactive_machine_id
        )

        self.vulnerability_ids = (
            vulnerability_ids
        )


@pytest.fixture
def seed(
    owner_session_factory: (
        sessionmaker[Session]
    ),
) -> Iterator[
    Seed
]:
    suffix = uuid4().hex[:12]

    enabled_source_id = uuid4()
    disabled_source_id = uuid4()

    enabled_source_code = (
        "SCHED_ENABLED_"
        + suffix.upper()
    )

    disabled_source_code = (
        "SCHED_DISABLED_"
        + suffix.upper()
    )

    active_organization_id = uuid4()
    inactive_organization_id = uuid4()

    active_machine_id = uuid4()
    inactive_machine_id = uuid4()

    active_component_a_id = uuid4()
    active_component_b_id = uuid4()
    inactive_component_id = uuid4()

    vulnerability_a_id = uuid4()
    vulnerability_b_id = uuid4()
    vulnerability_inactive_id = uuid4()

    exposure_a_id = uuid4()
    exposure_b_id = uuid4()
    exposure_inactive_id = uuid4()

    vulnerability_ids = (
        vulnerability_a_id,
        vulnerability_b_id,
        vulnerability_inactive_id,
    )

    with (
        owner_session_factory()
        as session
    ):
        session.add_all(
            [
                SourceModel(
                    id=enabled_source_id,
                    code=enabled_source_code,
                    name=(
                        "Scheduler enabled source"
                    ),
                    base_url=None,
                    enabled=True,
                    created_at=NOW,
                ),
                SourceModel(
                    id=disabled_source_id,
                    code=disabled_source_code,
                    name=(
                        "Scheduler disabled source"
                    ),
                    base_url=None,
                    enabled=False,
                    created_at=NOW,
                ),
            ]
        )

        session.add_all(
            [
                OrganizationModel(
                    id=active_organization_id,
                    name=(
                        "Scheduler Active "
                        + suffix
                    ),
                    slug=(
                        "scheduler-active-"
                        + suffix.lower()
                    ),
                    is_active=True,
                    created_at=NOW,
                ),
                OrganizationModel(
                    id=inactive_organization_id,
                    name=(
                        "Scheduler Inactive "
                        + suffix
                    ),
                    slug=(
                        "scheduler-inactive-"
                        + suffix.lower()
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
                    id=active_machine_id,
                    organization_id=(
                        active_organization_id
                    ),
                    machine_uid=uuid4(),
                    hostname=(
                        "SCHED-CVE-ACTIVE"
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
                        "SCHED-CVE-INACTIVE"
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

        session.add_all(
            [
                CanonicalVulnerabilityModel(
                    id=vulnerability_a_id,
                    status="active",
                    correlation_version=1,
                    merged_into_id=None,
                    created_at=NOW,
                    updated_at=NOW,
                ),
                CanonicalVulnerabilityModel(
                    id=vulnerability_b_id,
                    status="active",
                    correlation_version=1,
                    merged_into_id=None,
                    created_at=NOW,
                    updated_at=NOW,
                ),
                CanonicalVulnerabilityModel(
                    id=(
                        vulnerability_inactive_id
                    ),
                    status="active",
                    correlation_version=1,
                    merged_into_id=None,
                    created_at=NOW,
                    updated_at=NOW,
                ),
            ]
        )

        session.flush()

        session.add_all(
            [
                CanonicalVulnerabilityIdentifierModel(
                    id=uuid4(),
                    vulnerability_id=(
                        vulnerability_a_id
                    ),
                    namespace="CVE",
                    value=(
                        "CVE-2099-900001"
                    ),
                    is_primary=True,
                ),
                CanonicalVulnerabilityIdentifierModel(
                    id=uuid4(),
                    vulnerability_id=(
                        vulnerability_b_id
                    ),
                    namespace="CVE",
                    value=(
                        "CVE-2099-900002"
                    ),
                    is_primary=True,
                ),
                CanonicalVulnerabilityIdentifierModel(
                    id=uuid4(),
                    vulnerability_id=(
                        vulnerability_inactive_id
                    ),
                    namespace="CVE",
                    value=(
                        "CVE-2099-900003"
                    ),
                    is_primary=True,
                ),
            ]
        )

        session.add_all(
            [
                SoftwareComponentModel(
                    id=active_component_a_id,
                    machine_id=(
                        active_machine_id
                    ),
                    component_type="package",
                    name="scheduler-package-a",
                    normalized_name=(
                        "scheduler-package-a"
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
                    id=active_component_b_id,
                    machine_id=(
                        active_machine_id
                    ),
                    component_type="package",
                    name="scheduler-package-b",
                    normalized_name=(
                        "scheduler-package-b"
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
                    id=inactive_component_id,
                    machine_id=(
                        inactive_machine_id
                    ),
                    component_type="package",
                    name=(
                        "scheduler-package-inactive"
                    ),
                    normalized_name=(
                        "scheduler-package-inactive"
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

        session.flush()

        session.add_all(
            [
                VulnerabilityExposureModel(
                    id=exposure_a_id,
                    software_component_id=(
                        active_component_a_id
                    ),
                    canonical_vulnerability_id=(
                        vulnerability_a_id
                    ),
                    applicability_status=(
                        "confirmed"
                    ),
                    match_rule=(
                        "scheduler_support_test"
                    ),
                    match_version="1",
                    severity="HIGH",
                    priority="HIGH",
                    is_kev=False,
                    first_detected_at=NOW,
                    last_evaluated_at=NOW,
                ),
                VulnerabilityExposureModel(
                    id=exposure_b_id,
                    software_component_id=(
                        active_component_b_id
                    ),
                    canonical_vulnerability_id=(
                        vulnerability_b_id
                    ),
                    applicability_status=(
                        "potential"
                    ),
                    match_rule=(
                        "scheduler_support_test"
                    ),
                    match_version="1",
                    severity="MEDIUM",
                    priority="MEDIUM",
                    is_kev=False,
                    first_detected_at=NOW,
                    last_evaluated_at=NOW,
                ),
                VulnerabilityExposureModel(
                    id=exposure_inactive_id,
                    software_component_id=(
                        inactive_component_id
                    ),
                    canonical_vulnerability_id=(
                        vulnerability_inactive_id
                    ),
                    applicability_status=(
                        "confirmed"
                    ),
                    match_rule=(
                        "scheduler_support_test"
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
        enabled_source_code=(
            enabled_source_code
        ),
        enabled_source_id=(
            enabled_source_id
        ),
        disabled_source_code=(
            disabled_source_code
        ),
        active_organization_id=(
            active_organization_id
        ),
        inactive_organization_id=(
            inactive_organization_id
        ),
        active_machine_id=(
            active_machine_id
        ),
        inactive_machine_id=(
            inactive_machine_id
        ),
        vulnerability_ids=(
            vulnerability_ids
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
                    .id
                    .in_(
                        (
                            exposure_a_id,
                            exposure_b_id,
                            exposure_inactive_id,
                        )
                    )
                )
            )

            session.execute(
                delete(
                    SoftwareComponentModel
                )
                .where(
                    SoftwareComponentModel
                    .id
                    .in_(
                        (
                            active_component_a_id,
                            active_component_b_id,
                            inactive_component_id,
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
                            active_machine_id,
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
                    CanonicalVulnerabilityIdentifierModel
                )
                .where(
                    CanonicalVulnerabilityIdentifierModel
                    .vulnerability_id
                    .in_(
                        vulnerability_ids
                    )
                )
            )

            session.execute(
                delete(
                    CanonicalVulnerabilityModel
                )
                .where(
                    CanonicalVulnerabilityModel
                    .id
                    .in_(
                        vulnerability_ids
                    )
                )
            )

            session.execute(
                delete(
                    SourceModel
                )
                .where(
                    SourceModel.id.in_(
                        (
                            enabled_source_id,
                            disabled_source_id,
                        )
                    )
                )
            )

            session.commit()


def test_source_resolver_returns_enabled_source(
    owner_session_factory,
    seed,
):
    resolver = (
        SqlAlchemySchedulerSourceResolver(
            session_factory=(
                owner_session_factory
            )
        )
    )

    source_id = (
        resolver
        .resolve_enabled_source_id(
            seed.enabled_source_code
        )
    )

    assert (
        source_id
        == seed.enabled_source_id
    )


def test_source_resolver_rejects_disabled_source(
    owner_session_factory,
    seed,
):
    resolver = (
        SqlAlchemySchedulerSourceResolver(
            session_factory=(
                owner_session_factory
            )
        )
    )

    with pytest.raises(
        SchedulerSourceResolutionError,
        match="is disabled",
    ):
        resolver.resolve_enabled_source_id(
            seed.disabled_source_code
        )


def test_relevant_exposure_cves_are_targeted_and_paginated(
    owner_session_factory,
    seed,
):
    reader = (
        SqlAlchemyRelevantExposureCVEReader(
            session_factory=(
                owner_session_factory
            )
        )
    )

    # La base d'intégration peut déjà contenir
    # de vraies expositions.
    #
    # On positionne donc explicitement le curseur
    # juste avant les CVE synthétiques du test
    # au lieu de supposer que la base est vide.
    first_page = (
        reader.read_batch(
            after_cve_id=(
                "CVE-2099-900000"
            ),
            limit=1,
        )
    )

    assert first_page == (
        "CVE-2099-900001",
    )

    second_page = (
        reader.read_batch(
            after_cve_id=(
                first_page[-1]
            ),
            limit=1,
        )
    )

    assert second_page == (
        "CVE-2099-900002",
    )

    # CVE-2099-900003 appartient uniquement
    # à une organisation inactive.
    #
    # Elle ne doit donc jamais être la CVE
    # suivante retournée par le scheduler.
    third_page = (
        reader.read_batch(
            after_cve_id=(
                second_page[-1]
            ),
            limit=1,
        )
    )

    assert third_page != (
        "CVE-2099-900003",
    )