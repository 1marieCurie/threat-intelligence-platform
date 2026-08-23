from __future__ import annotations

import os
from datetime import (
    UTC,
    datetime,
)
from pathlib import Path
from uuid import uuid4

from dotenv import load_dotenv
from sqlalchemy import (
    Connection,
    create_engine,
    event,
    func,
    select,
    text,
)
from sqlalchemy.orm import (
    Session,
    SessionTransaction,
    sessionmaker,
)

from application.services.alert_evaluation_service import (
    AlertEvaluationService,
    ExposureAlertTransition,
)
from infrastructure.notifications.notification_adapter_factory import (
    load_notification_port,
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
)
from infrastructure.persistence.sqlalchemy.alert_unit_of_work import (
    SqlAlchemyAlertUnitOfWork,
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


def _require_environment_value(
    name: str,
) -> str:
    raw_value = os.environ.get(
        name
    )

    if raw_value is None:
        raise RuntimeError(
            f"{name} is not defined"
        )

    value = raw_value.strip()

    if not value:
        raise RuntimeError(
            f"{name} must not be empty"
        )

    return value


def main() -> None:
    backend = (
        _require_environment_value(
            "TIP_NOTIFICATION_BACKEND"
        )
        .lower()
    )

    if backend != "gmail":
        raise RuntimeError(
            (
                "TIP_NOTIFICATION_BACKEND "
                "must be gmail for this test"
            )
        )

    database_url = (
        _require_environment_value(
            "MIGRATION_DATABASE_URL"
        )
    )

    organization_slug = (
        _require_environment_value(
            "TIP_GMAIL_E2E_ORGANIZATION_SLUG"
        )
        .lower()
    )

    sender_email = (
        _require_environment_value(
            "TIP_GMAIL_SENDER_EMAIL"
        )
        .lower()
    )

    engine = create_engine(
        database_url,
        pool_pre_ping=True,
        future=True,
    )

    session_factory = sessionmaker(
        bind=engine,
        class_=OwnerSession,
        autoflush=False,
        expire_on_commit=False,
    )

    try:
        with session_factory() as session:
            organization = (
                session.scalar(
                    select(
                        OrganizationModel
                    )
                    .where(
                        func.lower(
                            OrganizationModel.slug
                        )
                        == organization_slug,
                        OrganizationModel
                        .is_active
                        .is_(True),
                    )
                    .limit(1)
                )
            )

            if organization is None:
                raise RuntimeError(
                    (
                        "No active organization "
                        "found for slug: "
                        f"{organization_slug}"
                    )
                )

            recipients = (
                session.execute(
                    select(
                        UserAccountModel
                    )
                    .where(
                        UserAccountModel
                        .organization_id
                        == organization.id,
                        UserAccountModel.role
                        == "security_responsible",
                        UserAccountModel
                        .is_active
                        .is_(True),
                    )
                    .order_by(
                        UserAccountModel.email
                    )
                )
                .scalars()
                .all()
            )

            if not recipients:
                raise RuntimeError(
                    (
                        "The organization has no "
                        "active security_responsible"
                    )
                )

            if len(recipients) != 1:
                recipient_emails = (
                    ", ".join(
                        recipient.email
                        for recipient
                        in recipients
                    )
                )

                raise RuntimeError(
                    (
                        "This manual Gmail E2E test "
                        "requires exactly one active "
                        "security_responsible. Found: "
                        f"{recipient_emails}"
                    )
                )

            recipient = recipients[0]

            if (
                recipient.email
                .strip()
                .lower()
                != sender_email
            ):
                raise RuntimeError(
                    (
                        "For this controlled test, "
                        "the security_responsible "
                        "email must be the same as "
                        "TIP_GMAIL_SENDER_EMAIL. "
                        f"Responsible: {recipient.email}; "
                        f"sender: {sender_email}"
                    )
                )

            organization_id = (
                organization.id
            )

            recipient_email = (
                recipient.email
            )

        now = datetime.now(
            UTC
        )

        suffix = (
            uuid4().hex[:10]
        )

        machine_id = uuid4()
        component_id = uuid4()
        canonical_id = uuid4()
        exposure_id = uuid4()

        hostname = (
            "GMAIL-E2E-"
            + suffix.upper()
        )

        cve_number = (
            int(
                uuid4().int
                % 900000
            )
            + 100000
        )

        synthetic_cve = (
            f"CVE-2099-{cve_number}"
        )

        with session_factory() as session:
            session.add(
                MachineModel(
                    id=machine_id,
                    organization_id=(
                        organization_id
                    ),
                    machine_uid=uuid4(),
                    hostname=hostname,
                    os_name="Windows",
                    os_version="11",
                    architecture="x64",
                    last_inventory_at=now,
                    created_at=now,
                    updated_at=now,
                )
            )

            session.add(
                CanonicalVulnerabilityModel(
                    id=canonical_id,
                    status="active",
                    correlation_version=1,
                    merged_into_id=None,
                    created_at=now,
                    updated_at=now,
                )
            )

            session.flush()

            session.add(
                CanonicalVulnerabilityIdentifierModel(
                    vulnerability_id=(
                        canonical_id
                    ),
                    namespace="CVE",
                    value=synthetic_cve,
                    is_primary=True,
                )
            )

            session.add(
                SoftwareComponentModel(
                    id=component_id,
                    machine_id=machine_id,
                    component_type="package",
                    name=(
                        "gmail-e2e-package"
                    ),
                    normalized_name=(
                        "gmail-e2e-package"
                    ),
                    version="1.0.0",
                    vendor=None,
                    normalized_vendor=None,
                    ecosystem="pypi",
                    external_id=None,
                    scope="global",
                    detected_by=(
                        "manual_gmail_e2e"
                    ),
                    created_at=now,
                    updated_at=now,
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
                        "manual_gmail_e2e_v1"
                    ),
                    match_version="1.0.0",
                    severity="CRITICAL",
                    priority="CRITICAL",
                    is_kev=False,
                    first_detected_at=now,
                    last_evaluated_at=now,
                )
            )

            session.commit()

        transition = (
            ExposureAlertTransition(
                exposure_id=exposure_id,
                canonical_vulnerability_id=(
                    canonical_id
                ),
                applicability_status=(
                    "confirmed"
                ),
                is_new_exposure=True,
                previous_priority=None,
                current_priority=(
                    "CRITICAL"
                ),
                previous_is_kev=None,
                current_is_kev=False,
            )
        )

        service = (
            AlertEvaluationService(
                unit_of_work=(
                    SqlAlchemyAlertUnitOfWork(
                        session_factory=(
                            session_factory
                        ), # pyright: ignore[reportArgumentType]
                    )
                ),
                notification_port=(
                    load_notification_port()
                ),
            )
        )

        result = service.evaluate(
            organization_id=(
                organization_id
            ),
            machine_id=machine_id,
            transitions=(
                transition,
            ),
            evaluated_at=now,
        )

        if (
            result.created_alert_count
            != 1
        ):
            raise RuntimeError(
                (
                    "Expected exactly one "
                    "created alert, got "
                    f"{result.created_alert_count}"
                )
            )

        alert_id = (
            result.created_alerts[0].id
        )

        with session_factory() as session:
            alert = session.scalar(
                select(
                    AlertModel
                ).where(
                    AlertModel.id
                    == alert_id
                )
            )

            if alert is None:
                raise RuntimeError(
                    "Persisted alert not found"
                )

            print()
            print(
                "================================"
            )
            print(
                "GMAIL_ALERT_E2E_RESULT"
            )
            print(
                "================================"
            )
            print(
                (
                    "organization_slug="
                    f"{organization_slug}"
                )
            )
            print(
                (
                    "recipient="
                    f"{recipient_email}"
                )
            )
            print(
                f"machine={hostname}"
            )
            print(
                f"cve={synthetic_cve}"
            )
            print(
                f"alert_id={alert.id}"
            )
            print(
                (
                    "alert_type="
                    f"{alert.alert_type}"
                )
            )
            print(
                f"status={alert.status}"
            )
            print(
                f"sent_at={alert.sent_at}"
            )
            print(
                (
                    "sent_notifications="
                    f"{result.sent_notification_count}"
                )
            )
            print(
                (
                    "failed_notifications="
                    f"{result.failed_notification_count}"
                )
            )
            print(
                "================================"
            )

            if (
                alert.status != "sent"
                or result
                .sent_notification_count
                != 1
                or result
                .failed_notification_count
                != 0
            ):
                raise RuntimeError(
                    (
                        "Gmail alert E2E did "
                        "not complete successfully"
                    )
                )

        print()
        print(
            "GMAIL_ALERT_E2E_OK"
        )
        print(
            (
                "Open the Alerts page "
                "to verify the persisted alert."
            )
        )

    finally:
        engine.dispose()


if __name__ == "__main__":
    main()