from __future__ import annotations

import os
from collections.abc import Iterator
from datetime import (
    UTC,
    date,
    datetime,
)
from pathlib import Path
from uuid import uuid4

import pytest
from dotenv import load_dotenv
from sqlalchemy import (
    Connection,
    create_engine,
    delete,
    event,
    text,
)
from sqlalchemy.orm import (
    Session,
    SessionTransaction,
    sessionmaker,
)

from infrastructure.persistence.models.assets import (
    AlertModel,
    MachineModel,
    OrganizationModel,
    SoftwareComponentModel,
    UserAccountModel,
    VulnerabilityExposureModel,
)
from infrastructure.persistence.models.canonical import (
    CanonicalVulnerabilityIdentifierModel,
    CanonicalVulnerabilityModel,
    CanonicalVulnerabilityWeaknessModel,
)
from infrastructure.persistence.models.normalized import (
    CWEWeaknessModel,
    EPSSScoreModel,
)
from infrastructure.persistence.sqlalchemy.readers.alert_read_repository import (
    SqlAlchemyAlertReadRepository,
)


PROJECT_ROOT = (
    Path(__file__)
    .resolve()
    .parents[2]
)

load_dotenv(
    dotenv_path=(
        PROJECT_ROOT / ".env"
    ),
    override=False,
)

pytestmark = pytest.mark.integration


T1 = datetime(
    2026,
    8,
    20,
    18,
    0,
    tzinfo=UTC,
)

T2 = datetime(
    2026,
    8,
    20,
    19,
    0,
    tzinfo=UTC,
)


class OwnerSession(Session):
    pass


@event.listens_for(
    OwnerSession,
    "after_begin",
)
def _activate_owner_role(
    session: Session,
    transaction: SessionTransaction,
    connection: Connection,
) -> None:
    del session
    del transaction

    connection.execute(
        text(
            "SET LOCAL ROLE "
            "threat_intel_owner"
        )
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

    factory = sessionmaker(
        bind=engine,
        class_=OwnerSession,
        autoflush=False,
        expire_on_commit=False,
    )

    try:
        yield factory  # type: ignore[misc]

    finally:
        engine.dispose()


def test_reads_rich_alert_detail_and_blocks_cross_tenant(
    owner_session_factory: sessionmaker[
        Session
    ],
) -> None:
    organization_id = uuid4()
    foreign_organization_id = uuid4()

    user_id = uuid4()

    machine_id = uuid4()

    component_id = uuid4()

    canonical_id = uuid4()

    exposure_id = uuid4()

    alert_id = uuid4()

    cve_id = (
        "CVE-2026-"
        + str(
            int(
                uuid4().int
                % 900000
            )
            + 100000
        )
    )

    ghsa_suffix = (
        uuid4()
        .hex[:12]
        .upper()
    )

    ghsa_id = (
        "GHSA-"
        + ghsa_suffix[0:4]
        + "-"
        + ghsa_suffix[4:8]
        + "-"
        + ghsa_suffix[8:12]
    )

    cwe_number = (
        int(
            uuid4().int
            % 8000
        )
        + 1000
    )

    cwe_id = (
        f"CWE-{cwe_number}"
    )

    email = (
        "security."
        + uuid4().hex
        + "@example.test"
    )

    try:
        # =============================================
        # Seed
        # =============================================

        with owner_session_factory() as session:
            session.add_all(
                [
                    OrganizationModel(
                        id=organization_id,
                        name=(
                            "alert-detail-"
                            + uuid4().hex
                        ),
                        is_active=True,
                        created_at=T1,
                    ),
                    OrganizationModel(
                        id=(
                            foreign_organization_id
                        ),
                        name=(
                            "alert-detail-foreign-"
                            + uuid4().hex
                        ),
                        is_active=True,
                        created_at=T1,
                    ),
                    CanonicalVulnerabilityModel(
                        id=canonical_id,
                        status="active",
                        correlation_version=1,
                        merged_into_id=None,
                        created_at=T1,
                        updated_at=T1,
                    ),
                    CWEWeaknessModel(
                        cwe_id=cwe_id,
                        name=(
                            "Test CWE weakness"
                        ),
                        description=(
                            "Detailed CWE description "
                            "used by the alert view."
                        ),
                    ),
                    EPSSScoreModel(
                        cve_id=cve_id,
                        epss_score=0.42,
                        percentile=0.95,
                        score_date=date(
                            2026,
                            8,
                            20,
                        ),
                        api_version="v1",
                    ),
                ]
            )

            session.flush()

            session.add_all(
                [
                    CanonicalVulnerabilityIdentifierModel(
                        vulnerability_id=(
                            canonical_id
                        ),
                        namespace="CVE",
                        value=cve_id,
                        is_primary=True,
                    ),
                    CanonicalVulnerabilityIdentifierModel(
                        vulnerability_id=(
                            canonical_id
                        ),
                        namespace="GHSA",
                        value=ghsa_id,
                        is_primary=False,
                    ),
                    CanonicalVulnerabilityWeaknessModel(
                        vulnerability_id=(
                            canonical_id
                        ),
                        cwe_id=cwe_id,
                        source=(
                            "github_advisory"
                        ),
                        source_record_key=(
                            ghsa_id
                        ),
                        normalized_record_id=(
                            ghsa_id
                        ),
                        observed_at=T1,
                        last_observed_at=T1,
                        source_modified_at=T1,
                    ),
                    UserAccountModel(
                        id=user_id,
                        organization_id=(
                            organization_id
                        ),
                        email=email,
                        display_name=(
                            "Security Responsible"
                        ),
                        role=(
                            "security_responsible"
                        ),
                        is_active=True,
                        created_at=T1,
                    ),
                    MachineModel(
                        id=machine_id,
                        organization_id=(
                            organization_id
                        ),
                        machine_uid=uuid4(),
                        hostname=(
                            "ALERT-DETAIL-MACHINE"
                        ),
                        os_name=(
                            "Windows 11 Pro"
                        ),
                        os_version="24H2",
                        architecture="x86_64",
                        last_inventory_at=T1,
                        created_at=T1,
                        updated_at=T1,
                    ),
                ]
            )

            session.flush()

            session.add(
                SoftwareComponentModel(
                    id=component_id,
                    machine_id=machine_id,
                    component_type=(
                        "package"
                    ),
                    name="requests",
                    normalized_name=(
                        "requests"
                    ),
                    version="2.31.0",
                    vendor=None,
                    normalized_vendor=None,
                    ecosystem="pypi",
                    external_id=None,
                    scope="global",
                    detected_by="pip_global",
                    created_at=T1,
                    updated_at=T1,
                )
            )

            session.flush()

            session.add(
                VulnerabilityExposureModel(
                    id=exposure_id,
                    software_component_id=(
                        component_id
                    ),
                    canonical_vulnerability_id=(
                        canonical_id
                    ),
                    applicability_status=(
                        "confirmed"
                    ),
                    match_rule=(
                        "test_alert_detail_v1"
                    ),
                    match_version="2.31.0",
                    severity="CRITICAL",
                    priority="CRITICAL",
                    is_kev=True,
                    first_detected_at=T1,
                    last_evaluated_at=T2,
                )
            )

            session.flush()

            session.add(
                AlertModel(
                    id=alert_id,
                    organization_id=(
                        organization_id
                    ),
                    machine_id=machine_id,
                    vulnerability_exposure_id=(
                        exposure_id
                    ),
                    canonical_vulnerability_id=(
                        canonical_id
                    ),
                    alert_type=(
                        "new_confirmed_critical_exposure"
                    ),
                    recipient_user_id=user_id,
                    status="pending",
                    deduplication_key=(
                        "test-alert-detail-"
                        + uuid4().hex
                    ),
                    created_at=T2,
                    sent_at=None,
                )
            )

            session.commit()

        repository = (
            SqlAlchemyAlertReadRepository(
                owner_session_factory
            )
        )

        # =============================================
        # Lecture tenant légitime
        # =============================================

        detail = (
            repository.get_alert_detail(
                organization_id=(
                    organization_id
                ),
                alert_id=alert_id,
            )
        )

        assert detail is not None

        assert (
            detail.alert_id
            == alert_id
        )

        assert (
            detail.alert_type
            == (
                "new_confirmed_critical_exposure"
            )
        )

        assert (
            detail.status
            == "pending"
        )

        assert (
            detail.primary_identifier
            == cve_id
        )

        assert (
            len(
                detail.identifiers
            )
            == 2
        )

        assert {
            item.value
            for item
            in detail.identifiers
        } == {
            cve_id,
            ghsa_id,
        }

        assert (
            detail.recipient.user_id
            == user_id
        )

        assert (
            detail.recipient.email
            == email
        )

        assert (
            detail.machine.machine_id
            == machine_id
        )

        assert (
            detail.machine.hostname
            == "ALERT-DETAIL-MACHINE"
        )

        assert (
            detail.component
            is not None
        )

        assert (
            detail.component.component_id
            == component_id
        )

        assert (
            detail.component.name
            == "requests"
        )

        assert (
            detail.component.version
            == "2.31.0"
        )

        assert (
            detail.exposure
            is not None
        )

        assert (
            detail.exposure.exposure_id
            == exposure_id
        )

        assert (
            detail.exposure
            .applicability_status
            == "confirmed"
        )

        assert (
            detail.exposure.severity
            == "CRITICAL"
        )

        assert (
            detail.exposure.priority
            == "CRITICAL"
        )

        assert (
            detail.exposure.is_kev
            is True
        )

        assert (
            detail.exposure.match_rule
            == "test_alert_detail_v1"
        )

        assert (
            detail.epss_score
            == pytest.approx(
                0.42
            )
        )

        assert (
            detail.epss_percentile
            == pytest.approx(
                0.95
            )
        )

        assert (
            detail.cvss_score
            is None
        )

        assert (
            detail.cvss_version
            is None
        )

        assert (
            len(
                detail.weaknesses
            )
            == 1
        )

        assert (
            detail.weaknesses[0]
            .cwe_id
            == cwe_id
        )

        assert (
            detail.weaknesses[0]
            .name
            == "Test CWE weakness"
        )

        assert (
            detail.weaknesses[0]
            .description
            == (
                "Detailed CWE description "
                "used by the alert view."
            )
        )

        # =============================================
        # Isolation cross-tenant
        # =============================================

        foreign_result = (
            repository.get_alert_detail(
                organization_id=(
                    foreign_organization_id
                ),
                alert_id=alert_id,
            )
        )

        assert (
            foreign_result
            is None
        )

    finally:
        # =============================================
        # Cleanup
        # =============================================

        with owner_session_factory() as session:
            session.execute(
                delete(
                    AlertModel
                )
                .where(
                    AlertModel.id
                    == alert_id
                )
            )

            session.execute(
                delete(
                    VulnerabilityExposureModel
                )
                .where(
                    VulnerabilityExposureModel.id
                    == exposure_id
                )
            )

            session.execute(
                delete(
                    SoftwareComponentModel
                )
                .where(
                    SoftwareComponentModel.id
                    == component_id
                )
            )

            session.execute(
                delete(
                    MachineModel
                )
                .where(
                    MachineModel.id
                    == machine_id
                )
            )

            session.execute(
                delete(
                    UserAccountModel
                )
                .where(
                    UserAccountModel.id
                    == user_id
                )
            )

            session.execute(
                delete(
                    CanonicalVulnerabilityWeaknessModel
                )
                .where(
                    CanonicalVulnerabilityWeaknessModel
                    .vulnerability_id
                    == canonical_id
                )
            )

            session.execute(
                delete(
                    CanonicalVulnerabilityIdentifierModel
                )
                .where(
                    CanonicalVulnerabilityIdentifierModel
                    .vulnerability_id
                    == canonical_id
                )
            )

            session.execute(
                delete(
                    EPSSScoreModel
                )
                .where(
                    EPSSScoreModel.cve_id
                    == cve_id
                )
            )

            session.execute(
                delete(
                    CanonicalVulnerabilityModel
                )
                .where(
                    CanonicalVulnerabilityModel.id
                    == canonical_id
                )
            )

            session.execute(
                delete(
                    CWEWeaknessModel
                )
                .where(
                    CWEWeaknessModel.cwe_id
                    == cwe_id
                )
            )

            session.execute(
                delete(
                    OrganizationModel
                )
                .where(
                    OrganizationModel.id.in_(
                        (
                            organization_id,
                            foreign_organization_id,
                        )
                    )
                )
            )

            session.commit()