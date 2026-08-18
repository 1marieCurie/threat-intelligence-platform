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
    select,
    text,
)
from sqlalchemy.orm import (
    Session,
    SessionTransaction,
    sessionmaker,
)

from application.ports.outbound.notification_port import (
    AlertNotification,
    NotificationDeliveryError,
)
from application.services.alert_evaluation_service import (
    AlertEvaluationService,
    ExposureAlertTransition,
)
from infrastructure.notifications.fake_notification_adapter import (
    FakeNotificationAdapter,
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
from infrastructure.persistence.sqlalchemy.alert_unit_of_work import (
    SqlAlchemyAlertUnitOfWork,
)
from infrastructure.persistence.sqlalchemy.repositories.alert_repository import (
    AlertRepositoryError,
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


class AlwaysFailNotificationAdapter:
    """
    Fake utilisé pour vérifier le chemin
    NotificationDeliveryError -> alert failed.
    """

    def __init__(
        self,
    ) -> None:
        self.attempts: list[
            AlertNotification
        ] = []

    def send(
        self,
        notification: AlertNotification,
    ) -> None:
        self.attempts.append(
            notification
        )

        raise NotificationDeliveryError(
            "Simulated delivery failure"
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


def test_real_postgresql_creates_notifies_deduplicates_fails_and_tenant_scopes_alerts(
    owner_session_factory: sessionmaker[
        Session
    ],
) -> None:
    organization_id = uuid4()
    foreign_organization_id = uuid4()

    machine_id = uuid4()
    foreign_machine_id = uuid4()

    component_id = uuid4()
    foreign_component_id = uuid4()

    canonical_id = uuid4()
    foreign_canonical_id = uuid4()

    exposure_id = uuid4()
    foreign_exposure_id = uuid4()

    responsible_id = uuid4()
    inactive_responsible_id = uuid4()
    staff_id = uuid4()
    foreign_responsible_id = uuid4()

    try:
        # =====================================================
        # Seed
        # =====================================================
        with owner_session_factory() as session:
            session.add_all(
                [
                    OrganizationModel(
                        id=organization_id,
                        name=(
                            "alert-e2e-"
                            + uuid4().hex
                        ),
                        is_active=True,
                        created_at=T1,
                    ),
                    OrganizationModel(
                        id=foreign_organization_id,
                        name=(
                            "alert-foreign-"
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
                    CanonicalVulnerabilityModel(
                        id=foreign_canonical_id,
                        status="active",
                        correlation_version=1,
                        merged_into_id=None,
                        created_at=T1,
                        updated_at=T1,
                    ),
                ]
            )

            session.flush()

            # =================================================
            # Utilisateurs
            # =================================================
            session.add_all(
                [
                    UserAccountModel(
                        id=responsible_id,
                        organization_id=(
                            organization_id
                        ),
                        email=(
                            "security."
                            + uuid4().hex
                            + "@example.test"
                        ),
                        display_name=(
                            "Security Responsible"
                        ),
                        role=(
                            "security_responsible"
                        ),
                        is_active=True,
                        created_at=T1,
                    ),
                    UserAccountModel(
                        id=inactive_responsible_id,
                        organization_id=(
                            organization_id
                        ),
                        email=(
                            "inactive."
                            + uuid4().hex
                            + "@example.test"
                        ),
                        display_name=(
                            "Inactive Responsible"
                        ),
                        role=(
                            "security_responsible"
                        ),
                        is_active=False,
                        created_at=T1,
                    ),
                    UserAccountModel(
                        id=staff_id,
                        organization_id=(
                            organization_id
                        ),
                        email=(
                            "staff."
                            + uuid4().hex
                            + "@example.test"
                        ),
                        display_name="Staff",
                        role="staff",
                        is_active=True,
                        created_at=T1,
                    ),
                    UserAccountModel(
                        id=foreign_responsible_id,
                        organization_id=(
                            foreign_organization_id
                        ),
                        email=(
                            "foreign."
                            + uuid4().hex
                            + "@example.test"
                        ),
                        display_name=(
                            "Foreign Responsible"
                        ),
                        role=(
                            "security_responsible"
                        ),
                        is_active=True,
                        created_at=T1,
                    ),
                ]
            )

            session.flush()

            # =================================================
            # Machines
            # =================================================
            session.add_all(
                [
                    MachineModel(
                        id=machine_id,
                        organization_id=(
                            organization_id
                        ),
                        machine_uid=uuid4(),
                        hostname=(
                            "alert-e2e-machine"
                        ),
                        os_name="Windows",
                        os_version="11",
                        architecture="x86_64",
                        last_inventory_at=T1,
                        created_at=T1,
                        updated_at=T1,
                    ),
                    MachineModel(
                        id=foreign_machine_id,
                        organization_id=(
                            foreign_organization_id
                        ),
                        machine_uid=uuid4(),
                        hostname=(
                            "foreign-alert-machine"
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

            # =================================================
            # Components
            # =================================================
            session.add_all(
                [
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
                    ),
                    SoftwareComponentModel(
                        id=foreign_component_id,
                        machine_id=(
                            foreign_machine_id
                        ),
                        component_type="package",
                        name="flask",
                        normalized_name="flask",
                        version="3.0.0",
                        vendor=None,
                        normalized_vendor=None,
                        ecosystem="pypi",
                        external_id=None,
                        scope="global",
                        detected_by="pip_global",
                        created_at=T1,
                        updated_at=T1,
                    ),
                ]
            )

            session.flush()

            # =================================================
            # Expositions
            # =================================================
            session.add_all(
                [
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
                            "test_rule_v1"
                        ),
                        match_version="1.0",
                        severity="CRITICAL",
                        priority="CRITICAL",
                        is_kev=False,
                        first_detected_at=T1,
                        last_evaluated_at=T2,
                    ),
                    VulnerabilityExposureModel(
                        id=foreign_exposure_id,
                        software_component_id=(
                            foreign_component_id
                        ),
                        canonical_vulnerability_id=(
                            foreign_canonical_id
                        ),
                        applicability_status=(
                            "confirmed"
                        ),
                        match_rule=(
                            "test_rule_v1"
                        ),
                        match_version="1.0",
                        severity="CRITICAL",
                        priority="CRITICAL",
                        is_kev=False,
                        first_detected_at=T1,
                        last_evaluated_at=T2,
                    ),
                ]
            )

            session.commit()

        # =====================================================
        # UoW
        # =====================================================
        unit_of_work = (
            SqlAlchemyAlertUnitOfWork(
                session_factory=(
                    owner_session_factory
                )
            )
        )

        # =====================================================
        # Adapter succès
        # =====================================================
        notification_adapter = (
            FakeNotificationAdapter()
        )

        service = (
            AlertEvaluationService(
                unit_of_work=unit_of_work,
                notification_port=(
                    notification_adapter
                ),
            )
        )

        # =====================================================
        # HIGH -> CRITICAL
        # =====================================================
        transition = (
            ExposureAlertTransition(
                exposure_id=exposure_id,
                canonical_vulnerability_id=(
                    canonical_id
                ),
                applicability_status=(
                    "confirmed"
                ),
                is_new_exposure=False,
                previous_priority="HIGH",
                current_priority="CRITICAL",
                previous_is_kev=False,
                current_is_kev=False,
            )
        )

        # =====================================================
        # Premier passage
        # =====================================================
        result = service.evaluate(
            organization_id=(
                organization_id
            ),
            machine_id=machine_id,
            transitions=(
                transition,
            ),
            evaluated_at=T2,
        )

        assert (
            result.transition_count
            == 1
        )

        assert (
            result.recipient_count
            == 1
        )

        assert (
            result.candidate_event_count
            == 1
        )

        assert (
            result.attempted_alert_count
            == 1
        )

        assert (
            result.created_alert_count
            == 1
        )

        assert (
            result.sent_notification_count
            == 1
        )

        assert (
            result.failed_notification_count
            == 0
        )

        assert len(
            notification_adapter
            .attempted_notifications
        ) == 1

        assert len(
            notification_adapter
            .sent_notifications
        ) == 1

        created = (
            result.created_alerts[0]
        )

        # L'objet retourné correspond à la création
        # initiale, donc avant le passage final à sent.
        assert (
            created.status
            == "pending"
        )

        assert (
            created.sent_at
            is None
        )

        assert (
            created.organization_id
            == organization_id
        )

        assert (
            created.machine_id
            == machine_id
        )

        assert (
            created.vulnerability_exposure_id
            == exposure_id
        )

        assert (
            created.canonical_vulnerability_id
            == canonical_id
        )

        assert (
            created.recipient_user_id
            == responsible_id
        )

        assert (
            created.alert_type
            == (
                "priority_transition_to_critical"
            )
        )

        expected_key = (
            "alert/v1:"
            "priority_transition_to_critical:"
            f"{exposure_id}:"
            "recipient:"
            f"{responsible_id}"
        )

        assert (
            created.deduplication_key
            == expected_key
        )

        # =====================================================
        # Vérification DB après notification réussie
        # =====================================================
        with owner_session_factory() as session:
            persisted_alerts = (
                session.execute(
                    select(
                        AlertModel
                    )
                    .where(
                        AlertModel.organization_id
                        == organization_id
                    )
                )
                .scalars()
                .all()
            )

            assert len(
                persisted_alerts
            ) == 1

            persisted = (
                persisted_alerts[0]
            )

            assert (
                persisted.recipient_user_id
                == responsible_id
            )

            # staff, inactive et foreign
            # ne reçoivent rien.
            assert (
                persisted.recipient_user_id
                != staff_id
            )

            assert (
                persisted.recipient_user_id
                != inactive_responsible_id
            )

            assert (
                persisted.recipient_user_id
                != foreign_responsible_id
            )

            assert (
                persisted.status
                == "sent"
            )

            assert (
                persisted.sent_at
                == T2
            )

        # =====================================================
        # Deuxième passage identique
        #
        # PostgreSQL déduplique.
        # L'alerte existante ne doit PAS être renvoyée.
        # =====================================================
        second = service.evaluate(
            organization_id=(
                organization_id
            ),
            machine_id=machine_id,
            transitions=(
                transition,
            ),
            evaluated_at=T2,
        )

        assert (
            second.attempted_alert_count
            == 1
        )

        assert (
            second.created_alert_count
            == 0
        )

        assert (
            second.sent_notification_count
            == 0
        )

        assert (
            second.failed_notification_count
            == 0
        )

        # Toujours un seul véritable envoi.
        assert len(
            notification_adapter
            .attempted_notifications
        ) == 1

        assert len(
            notification_adapter
            .sent_notifications
        ) == 1

        with owner_session_factory() as session:
            alerts_after_replay = (
                session.execute(
                    select(
                        AlertModel
                    )
                    .where(
                        AlertModel.organization_id
                        == organization_id
                    )
                )
                .scalars()
                .all()
            )

            assert len(
                alerts_after_replay
            ) == 1

            assert (
                alerts_after_replay[0].status
                == "sent"
            )

        # =====================================================
        # Chemin FAILED
        #
        # On utilise un autre événement :
        # nouvelle exposition confirmed CRITICAL.
        #
        # Le alert_type est différent, donc la clé de
        # déduplication est différente.
        # =====================================================
        failing_adapter = (
            AlwaysFailNotificationAdapter()
        )

        failing_service = (
            AlertEvaluationService(
                unit_of_work=unit_of_work,
                notification_port=(
                    failing_adapter
                ),
            )
        )

        new_critical_transition = (
            ExposureAlertTransition(
                exposure_id=(
                    exposure_id
                ),
                canonical_vulnerability_id=(
                    canonical_id
                ),
                applicability_status=(
                    "confirmed"
                ),
                is_new_exposure=True,
                previous_priority=None,
                current_priority="CRITICAL",
                previous_is_kev=None,
                current_is_kev=False,
            )
        )

        failed_result = (
            failing_service.evaluate(
                organization_id=(
                    organization_id
                ),
                machine_id=machine_id,
                transitions=(
                    new_critical_transition,
                ),
                evaluated_at=T2,
            )
        )

        assert (
            failed_result.transition_count
            == 1
        )

        assert (
            failed_result.recipient_count
            == 1
        )

        assert (
            failed_result.candidate_event_count
            == 1
        )

        assert (
            failed_result.attempted_alert_count
            == 1
        )

        assert (
            failed_result.created_alert_count
            == 1
        )

        assert (
            failed_result.sent_notification_count
            == 0
        )

        assert (
            failed_result.failed_notification_count
            == 1
        )

        assert len(
            failing_adapter.attempts
        ) == 1

        failed_created = (
            failed_result.created_alerts[0]
        )

        assert (
            failed_created.alert_type
            == (
                "new_confirmed_critical_exposure"
            )
        )

        # Au moment de l'INSERT, elle était pending.
        assert (
            failed_created.status
            == "pending"
        )

        assert (
            failed_created.sent_at
            is None
        )

        # =====================================================
        # Vérification DB du chemin failed
        # =====================================================
        with owner_session_factory() as session:
            failed_persisted = (
                session.get(
                    AlertModel,
                    failed_created.id,
                )
            )

            assert (
                failed_persisted
                is not None
            )

            assert (
                failed_persisted.status
                == "failed"
            )

            assert (
                failed_persisted.sent_at
                is None
            )

            all_local_alerts = (
                session.execute(
                    select(
                        AlertModel
                    )
                    .where(
                        AlertModel.organization_id
                        == organization_id
                    )
                )
                .scalars()
                .all()
            )

            # Une sent + une failed.
            assert len(
                all_local_alerts
            ) == 2

        # =====================================================
        # Tentative cross-tenant
        #
        # organisation A + machine A
        # mais exposure appartenant à B.
        # =====================================================
        malicious_transition = (
            ExposureAlertTransition(
                exposure_id=(
                    foreign_exposure_id
                ),
                canonical_vulnerability_id=(
                    foreign_canonical_id
                ),
                applicability_status=(
                    "confirmed"
                ),
                is_new_exposure=False,
                previous_priority="HIGH",
                current_priority="CRITICAL",
                previous_is_kev=False,
                current_is_kev=False,
            )
        )

        attempted_before_attack = len(
            notification_adapter
            .attempted_notifications
        )

        with pytest.raises(
            AlertRepositoryError,
            match="does not belong",
        ):
            service.evaluate(
                organization_id=(
                    organization_id
                ),
                machine_id=machine_id,
                transitions=(
                    malicious_transition,
                ),
                evaluated_at=T2,
            )

        # Aucun envoi ne doit être tenté,
        # car la validation repository échoue
        # avant tout appel NotificationPort.
        assert len(
            notification_adapter
            .attempted_notifications
        ) == attempted_before_attack

        # =====================================================
        # Vérification finale :
        # aucune troisième alerte hostile.
        # =====================================================
        with owner_session_factory() as session:
            persisted = (
                session.execute(
                    select(
                        AlertModel
                    )
                    .where(
                        AlertModel.organization_id
                        == organization_id
                    )
                )
                .scalars()
                .all()
            )

            assert len(
                persisted
            ) == 2

            statuses = {
                alert.status
                for alert in persisted
            }

            assert statuses == {
                "sent",
                "failed",
            }

    finally:
        # =====================================================
        # Cleanup inverse des FK
        # =====================================================
        with owner_session_factory() as session:
            session.execute(
                delete(
                    AlertModel
                ).where(
                    AlertModel.organization_id
                    .in_(
                        (
                            organization_id,
                            foreign_organization_id,
                        )
                    )
                )
            )

            session.execute(
                delete(
                    VulnerabilityExposureModel
                ).where(
                    VulnerabilityExposureModel.id
                    .in_(
                        (
                            exposure_id,
                            foreign_exposure_id,
                        )
                    )
                )
            )

            session.execute(
                delete(
                    SoftwareComponentModel
                ).where(
                    SoftwareComponentModel.id
                    .in_(
                        (
                            component_id,
                            foreign_component_id,
                        )
                    )
                )
            )

            session.execute(
                delete(
                    MachineModel
                ).where(
                    MachineModel.id
                    .in_(
                        (
                            machine_id,
                            foreign_machine_id,
                        )
                    )
                )
            )

            session.execute(
                delete(
                    UserAccountModel
                ).where(
                    UserAccountModel.id
                    .in_(
                        (
                            responsible_id,
                            inactive_responsible_id,
                            staff_id,
                            foreign_responsible_id,
                        )
                    )
                )
            )

            session.execute(
                delete(
                    OrganizationModel
                ).where(
                    OrganizationModel.id
                    .in_(
                        (
                            organization_id,
                            foreign_organization_id,
                        )
                    )
                )
            )

            session.execute(
                delete(
                    CanonicalVulnerabilityModel
                ).where(
                    CanonicalVulnerabilityModel.id
                    .in_(
                        (
                            canonical_id,
                            foreign_canonical_id,
                        )
                    )
                )
            )

            session.commit()