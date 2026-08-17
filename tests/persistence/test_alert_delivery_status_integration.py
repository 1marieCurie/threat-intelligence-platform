from __future__ import annotations

import os
from collections.abc import Iterator
from datetime import (
    UTC,
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

from application.ports.outbound.alert_repository import (
    AlertSentUpdate,
    PendingAlertCreate,
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
    CanonicalVulnerabilityModel,
)
from infrastructure.persistence.sqlalchemy.repositories.alert_repository import (
    SqlAlchemyAlertRepository,
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
    17,
    18,
    0,
    tzinfo=UTC,
)

T2 = datetime(
    2026,
    8,
    17,
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
        yield factory

    finally:
        engine.dispose()


def test_real_postgresql_alert_status_transitions(
    owner_session_factory,
) -> None:
    organization_id = uuid4()
    machine_id = uuid4()
    user_id = uuid4()

    component_id = uuid4()
    canonical_id = uuid4()
    exposure_id = uuid4()

    sent_alert_id = None
    failed_alert_id = None

    try:
        with owner_session_factory() as session:
            session.add_all(
                [
                    OrganizationModel(
                        id=organization_id,
                        name=(
                            "notification-e2e-"
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
                ]
            )

            session.flush()

            session.add_all(
                [
                    UserAccountModel(
                        id=user_id,
                        organization_id=(
                            organization_id
                        ),
                        email=(
                            "security."
                            + uuid4().hex
                            + "@example.test"
                        ),
                        display_name="Security",
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
                            "notification-e2e"
                        ),
                        os_name="Windows",
                        os_version="11",
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
                    component_type="package",
                    name="requests",
                    normalized_name="requests",
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
                    match_rule="test_rule_v1",
                    match_version="1",
                    severity="CRITICAL",
                    priority="CRITICAL",
                    is_kev=False,
                    first_detected_at=T1,
                    last_evaluated_at=T1,
                )
            )

            session.commit()

        # Deux alertes pending distinctes.
        with owner_session_factory() as session:
            repository = (
                SqlAlchemyAlertRepository(
                    session=session
                )
            )

            created = (
                repository.insert_pending_many(
                    alerts=(
                        PendingAlertCreate(
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
                            recipient_user_id=(
                                user_id
                            ),
                            deduplication_key=(
                                "notification-test:"
                                + uuid4().hex
                            ),
                            created_at=T1,
                        ),
                        PendingAlertCreate(
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
                                "priority_transition_to_critical"
                            ),
                            recipient_user_id=(
                                user_id
                            ),
                            deduplication_key=(
                                "notification-test:"
                                + uuid4().hex
                            ),
                            created_at=T1,
                        ),
                    )
                )
            )

            assert len(
                created
            ) == 2

            sent_alert_id = (
                created[0].id
            )

            failed_alert_id = (
                created[1].id
            )

            assert (
                repository.mark_sent_many(
                    organization_id=(
                        organization_id
                    ),
                    updates=(
                        AlertSentUpdate(
                            alert_id=(
                                sent_alert_id
                            ),
                            sent_at=T2,
                        ),
                    ),
                )
                == 1
            )

            assert (
                repository.mark_failed_many(
                    organization_id=(
                        organization_id
                    ),
                    alert_ids=(
                        failed_alert_id,
                    ),
                )
                == 1
            )

            session.commit()

        with owner_session_factory() as session:
            sent = session.get(
                AlertModel,
                sent_alert_id,
            )

            failed = session.get(
                AlertModel,
                failed_alert_id,
            )

            assert sent is not None
            assert failed is not None

            assert sent.status == "sent"
            assert sent.sent_at == T2

            assert failed.status == "failed"
            assert failed.sent_at is None

            # sent ne doit jamais redevenir failed.
            repository = (
                SqlAlchemyAlertRepository(
                    session=session
                )
            )

            assert (
                repository.mark_failed_many(
                    organization_id=(
                        organization_id
                    ),
                    alert_ids=(
                        sent_alert_id,
                    ),
                )
                == 0
            )

            session.commit()

    finally:
        with owner_session_factory() as session:
            session.execute(
                delete(
                    AlertModel
                ).where(
                    AlertModel.organization_id
                    == organization_id
                )
            )

            session.execute(
                delete(
                    VulnerabilityExposureModel
                ).where(
                    VulnerabilityExposureModel.id
                    == exposure_id
                )
            )

            session.execute(
                delete(
                    SoftwareComponentModel
                ).where(
                    SoftwareComponentModel.id
                    == component_id
                )
            )

            session.execute(
                delete(
                    MachineModel
                ).where(
                    MachineModel.id
                    == machine_id
                )
            )

            session.execute(
                delete(
                    UserAccountModel
                ).where(
                    UserAccountModel.id
                    == user_id
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

            session.execute(
                delete(
                    CanonicalVulnerabilityModel
                ).where(
                    CanonicalVulnerabilityModel.id
                    == canonical_id
                )
            )

            session.commit()