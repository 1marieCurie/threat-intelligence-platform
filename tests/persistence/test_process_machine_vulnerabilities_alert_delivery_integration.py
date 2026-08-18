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

from application.services.alert_evaluation_policy_v1 import (
    AlertEvaluationPolicyV1,
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


PROJECT_ROOT = Path(__file__).resolve().parents[2]

load_dotenv(
    dotenv_path=PROJECT_ROOT / ".env",
    override=False,
)


pytestmark = pytest.mark.integration


T1 = datetime(
    2026,
    8,
    18,
    12,
    0,
    tzinfo=UTC,
)

T2 = datetime(
    2026,
    8,
    18,
    13,
    0,
    tzinfo=UTC,
)


class OwnerSession(Session):
    """
    Session PostgreSQL réservée à ce test.

    Chaque transaction utilise le rôle
    threat_intel_owner.
    """


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
        yield factory # type: ignore

    finally:
        engine.dispose()


def test_process_machine_vulnerabilities_delivers_kev_and_critical_alerts(
    owner_session_factory: sessionmaker[
        Session
    ],
) -> None:
    organization_id = uuid4()
    responsible_user_id = uuid4()
    machine_id = uuid4()
    component_id = uuid4()
    canonical_id = uuid4()
    exposure_id = uuid4()

    fake_notification_adapter = (
        FakeNotificationAdapter(
            fail_for_alert_ids=set(), # type: ignore
        )
    )

    try:
        # =====================================================
        # Seed initial
        #
        # Exposition :
        # - confirmed
        # - HIGH
        # - non-KEV
        #
        # L'ordre des flush est volontaire :
        #
        # organization
        #     ├── user_account
        #     └── machine
        #             └── software_component
        #                       └── vulnerability_exposure
        #
        # canonical_vulnerability est indépendant du tenant,
        # mais doit exister avant vulnerability_exposure.
        # =====================================================
        with owner_session_factory() as session:
            organization = (
                OrganizationModel(
                    id=organization_id,
                    name=(
                        "alert-e2e-"
                        + uuid4().hex
                    ),
                    is_active=True,
                    created_at=T1,
                )
            )

            responsible = (
                UserAccountModel(
                    id=responsible_user_id,
                    organization_id=(
                        organization_id
                    ),
                    email=(
                        "security-"
                        + uuid4().hex[:12]
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
                )
            )

            machine = (
                MachineModel(
                    id=machine_id,
                    organization_id=(
                        organization_id
                    ),
                    machine_uid=uuid4(),
                    hostname=(
                        "alert-e2e-"
                        + uuid4().hex[:12]
                    ),
                    os_name="Windows",
                    os_version="11",
                    architecture="x64",
                    last_inventory_at=T1,
                    created_at=T1,
                    updated_at=T1,
                )
            )

            component = (
                SoftwareComponentModel(
                    id=component_id,
                    machine_id=machine_id,
                    component_type="package",
                    name="example-package",
                    normalized_name=(
                        "example-package"
                    ),
                    version="1.0.0",
                    vendor=None,
                    normalized_vendor=None,
                    ecosystem="pypi",
                    external_id=None,
                    scope="global",
                    detected_by="e2e-test",
                    created_at=T1,
                    updated_at=T1,
                )
            )

            canonical = (
                CanonicalVulnerabilityModel(
                    id=canonical_id,
                    status="active",
                    correlation_version=1,
                    merged_into_id=None,
                    created_at=T1,
                    updated_at=T1,
                )
            )

            exposure = (
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
                        "e2e_confirmed_match"
                    ),
                    match_version="1.0.0",
                    severity="HIGH",
                    priority="HIGH",
                    is_kev=False,
                    first_detected_at=T1,
                    last_evaluated_at=T1,
                )
            )

            # -------------------------------------------------
            # 1. Parent tenant
            # -------------------------------------------------
            session.add(
                organization
            )
            session.flush()

            # -------------------------------------------------
            # 2. Objets dépendant de l'organisation
            #    + vulnérabilité canonique indépendante
            # -------------------------------------------------
            session.add_all(
                [
                    responsible,
                    machine,
                    canonical,
                ]
            )
            session.flush()

            # -------------------------------------------------
            # 3. SoftwareComponent dépend de Machine
            # -------------------------------------------------
            session.add(
                component
            )
            session.flush()

            # -------------------------------------------------
            # 4. Exposure dépend de :
            #    - SoftwareComponent
            #    - CanonicalVulnerability
            # -------------------------------------------------
            session.add(
                exposure
            )

            session.commit()

        # =====================================================
        # Vérification de l'état initial
        # =====================================================
        with owner_session_factory() as session:
            exposure = session.get(
                VulnerabilityExposureModel,
                exposure_id,
            )

            assert exposure is not None

            assert (
                exposure.applicability_status
                == "confirmed"
            )

            assert (
                exposure.priority
                == "HIGH"
            )

            assert (
                exposure.is_kev
                is False
            )

        # =====================================================
        # Simulation du résultat de la réévaluation
        #
        # HIGH / non-KEV
        #
        #          ↓
        #
        # CRITICAL / KEV
        #
        # Le nouvel état de l'exposition est persisté avant
        # l'évaluation des événements d'alerte.
        # =====================================================
        with owner_session_factory() as session:
            exposure = session.get(
                VulnerabilityExposureModel,
                exposure_id,
            )

            assert exposure is not None

            exposure.priority = (
                "CRITICAL"
            )
            exposure.is_kev = True
            exposure.last_evaluated_at = (
                T2
            )

            session.commit()

        # =====================================================
        # Transition réelle attendue par AlertEvaluationService.
        #
        # Scénario :
        #
        # - exposition existante
        # - confirmed
        # - HIGH -> CRITICAL
        # - non-KEV -> KEV
        #
        # Deux règles V1 doivent donc matcher :
        #
        # 1. confirmed_exposure_entered_kev
        # 2. priority_transition_to_critical
        # =====================================================
        transition = ExposureAlertTransition(
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
            current_is_kev=True,
        )

        # =====================================================
        # Composition réelle :
        #
        # AlertEvaluationService
        #     ↓
        # SqlAlchemyAlertUnitOfWork
        #     ↓
        # PostgreSQL
        #
        # NotificationPort :
        #     FakeNotificationAdapter
        # =====================================================
        service = (
            AlertEvaluationService(
                unit_of_work=(
                    SqlAlchemyAlertUnitOfWork(
                        session_factory=(
                            owner_session_factory
                        ),
                    )
                ),
                notification_port=(
                    fake_notification_adapter
                ),
                policy=(
                    AlertEvaluationPolicyV1()
                ),
            )
        )

        # =====================================================
        # Exécution
        # =====================================================
        result = service.evaluate(
            organization_id=(
                organization_id
            ),
            machine_id=(
                machine_id
            ),
            transitions=(
                transition,
            ),
            evaluated_at=T2,
        )

        # =====================================================
        # Résultat applicatif
        #
        # La même exposition déclenche deux événements
        # indépendants :
        #
        # - entrée dans KEV
        # - transition vers CRITICAL
        # =====================================================
        assert (
            result.created_alert_count
            == 2
        )

        assert (
            result.transition_count
            == 1
        )

        assert (
            result.candidate_event_count
            == 2
        )

        assert (
            result.attempted_alert_count
            == 2
        )

        assert (
            result.sent_notification_count
            == 2
        )

        assert (
            result.failed_notification_count
            == 0
        )

        # =====================================================
        # Vérification PostgreSQL
        # =====================================================
        with owner_session_factory() as session:
            alerts = (
                session.execute(
                    select(
                        AlertModel
                    )
                    .where(
                        (
                            AlertModel.organization_id
                            == organization_id
                        ),
                        (
                            AlertModel.machine_id
                            == machine_id
                        ),
                        (
                            AlertModel
                            .vulnerability_exposure_id
                            == exposure_id
                        ),
                    )
                    .order_by(
                        AlertModel.alert_type
                    )
                )
                .scalars()
                .all()
            )

            assert (
                len(alerts)
                == 2
            )

            assert {
                alert.alert_type
                for alert in alerts
            } == {
                (
                    "confirmed_exposure_"
                    "entered_kev"
                ),
                (
                    "priority_transition_"
                    "to_critical"
                ),
            }

            # ---------------------------------------------
            # Destinataire :
            # uniquement security_responsible
            # ---------------------------------------------
            assert all(
                (
                    alert.recipient_user_id
                    == responsible_user_id
                )
                for alert in alerts
            )

            # ---------------------------------------------
            # FakeNotificationAdapter réussit :
            # les alertes doivent être sent.
            # ---------------------------------------------
            assert all(
                alert.status == "sent"
                for alert in alerts
            )

            assert all(
                alert.sent_at is not None
                for alert in alerts
            )

            # ---------------------------------------------
            # Les deux types d'alerte sont distincts,
            # donc deux clés de déduplication distinctes.
            # ---------------------------------------------
            deduplication_keys = {
                alert.deduplication_key
                for alert in alerts
            }

            assert (
                len(
                    deduplication_keys
                )
                == 2
            )

            assert all(
                bool(
                    alert.deduplication_key
                )
                for alert in alerts
            )

            # ---------------------------------------------
            # Vérification des références métier.
            # ---------------------------------------------
            assert all(
                (
                    alert.organization_id
                    == organization_id
                )
                for alert in alerts
            )

            assert all(
                (
                    alert.machine_id
                    == machine_id
                )
                for alert in alerts
            )

            assert all(
                (
                    alert
                    .canonical_vulnerability_id
                    == canonical_id
                )
                for alert in alerts
            )

            assert all(
                (
                    alert
                    .vulnerability_exposure_id
                    == exposure_id
                )
                for alert in alerts
            )

        # =====================================================
        # Vérification NotificationPort
        #
        # Une notification doit avoir été envoyée pour
        # chacune des deux alertes persistées.
        #
        # FakeNotificationAdapter expose les notifications
        # réussies via sent_notifications.
        # =====================================================
        assert (
            len(
                fake_notification_adapter
                .sent_notifications
            )
            == 2
        )

    finally:
        # =====================================================
        # Cleanup ciblé.
        #
        # Ordre inverse des dépendances FK.
        #
        # Aucune donnée globale ou appartenant à un autre
        # tenant ne doit être supprimée.
        # =====================================================
        with owner_session_factory() as session:
            session.execute(
                delete(
                    AlertModel
                ).where(
                    (
                        AlertModel.organization_id
                        == organization_id
                    )
                )
            )

            session.execute(
                delete(
                    VulnerabilityExposureModel
                ).where(
                    (
                        VulnerabilityExposureModel.id
                        == exposure_id
                    )
                )
            )

            session.execute(
                delete(
                    SoftwareComponentModel
                ).where(
                    (
                        SoftwareComponentModel.id
                        == component_id
                    )
                )
            )

            session.execute(
                delete(
                    MachineModel
                ).where(
                    (
                        MachineModel.id
                        == machine_id
                    )
                )
            )

            session.execute(
                delete(
                    UserAccountModel
                ).where(
                    (
                        UserAccountModel.id
                        == responsible_user_id
                    )
                )
            )

            session.execute(
                delete(
                    OrganizationModel
                ).where(
                    (
                        OrganizationModel.id
                        == organization_id
                    )
                )
            )

            session.execute(
                delete(
                    CanonicalVulnerabilityModel
                ).where(
                    (
                        CanonicalVulnerabilityModel.id
                        == canonical_id
                    )
                )
            )

            session.commit()