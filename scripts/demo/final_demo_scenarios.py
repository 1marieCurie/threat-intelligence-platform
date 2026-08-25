from __future__ import annotations

import argparse
import os
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4

from dotenv import load_dotenv
from sqlalchemy import Connection, delete, event, func, select, text
from sqlalchemy.orm import Session, SessionTransaction, sessionmaker
from sqlalchemy import create_engine

from application.services.alert_evaluation_service import (
    AlertEvaluationResult,
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
)
from infrastructure.persistence.sqlalchemy.alert_unit_of_work import (
    SqlAlchemyAlertUnitOfWork,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]
load_dotenv(PROJECT_ROOT / ".env", override=False)

DEMO_DETECTED_BY = "final_demo_scenario"
CONFIRMED_HOSTNAME = "PFA-DEMO-CONFIRMED"
POTENTIAL_HOSTNAME = "PFA-DEMO-POTENTIAL"
NEW_CRITICAL_HOSTNAME = "PFA-DEMO-NEW-CRITICAL"
DEMO_HOSTNAMES = (
    CONFIRMED_HOSTNAME,
    POTENTIAL_HOSTNAME,
    NEW_CRITICAL_HOSTNAME,
)

DEFAULT_CVE = "CVE-2021-44228"
DEMO_COMPONENT_NAME = "log4j-core"
DEMO_COMPONENT_VERSION = "2.14.1"


class OwnerSession(Session):
    pass


@event.listens_for(OwnerSession, "after_begin")
def _activate_owner_role(
    session: Session,
    transaction: SessionTransaction,
    connection: Connection,
) -> None:
    del session
    del transaction
    connection.execute(text("SET LOCAL ROLE threat_intel_owner"))


def _require_env(name: str) -> str:
    value = os.getenv(name)
    if value is None or not value.strip():
        raise RuntimeError(f"{name} is not defined")
    return value.strip()


def _session_factory() -> tuple[
    sessionmaker[Session],
    object,
]:
    database_url = _require_env("MIGRATION_DATABASE_URL")
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
    return factory, engine


def _demo_slug() -> str:
    return _require_env("TIP_DEMO_ORGANIZATION_SLUG").lower()


def _demo_cve() -> str:
    value = os.getenv("TIP_DEMO_CVE_ID", DEFAULT_CVE).strip().upper()
    if not value.startswith("CVE-"):
        raise RuntimeError("TIP_DEMO_CVE_ID must be a CVE identifier")
    return value


def _organization_id(factory: sessionmaker[Session]) -> UUID:
    slug = _demo_slug()
    with factory() as session:
        organization_id = session.scalar(
            select(OrganizationModel.id)
            .where(
                func.lower(OrganizationModel.slug) == slug,
                OrganizationModel.is_active.is_(True),
            )
            .limit(1)
        )
    if organization_id is None:
        raise RuntimeError(
            f"No active organization found for TIP_DEMO_ORGANIZATION_SLUG={slug}"
        )
    return organization_id


def _responsibles(
    factory: sessionmaker[Session],
    organization_id: UUID,
) -> list[tuple[UUID, str]]:
    with factory() as session:
        rows = session.execute(
            select(UserAccountModel.id, UserAccountModel.email)
            .where(
                UserAccountModel.organization_id == organization_id,
                UserAccountModel.role == "security_responsible",
                UserAccountModel.is_active.is_(True),
            )
            .order_by(UserAccountModel.email)
        ).all()
    return [(row[0], row[1]) for row in rows]


def _canonical_vulnerability_id(factory: sessionmaker[Session]) -> UUID:
    cve = _demo_cve()
    with factory() as session:
        canonical_id = session.scalar(
            select(CanonicalVulnerabilityIdentifierModel.vulnerability_id)
            .where(
                CanonicalVulnerabilityIdentifierModel.namespace == "CVE",
                CanonicalVulnerabilityIdentifierModel.value == cve,
            )
            .limit(1)
        )
    if canonical_id is None:
        raise RuntimeError(
            f"{cve} is not present in canonical data. Run the normal ingestion first "
            "or set TIP_DEMO_CVE_ID to another real CVE already ingested."
        )
    return canonical_id


def _find_demo_exposure(
    factory: sessionmaker[Session],
    hostname: str,
) -> tuple[VulnerabilityExposureModel, UUID]:
    with factory() as session:
        row = session.execute(
            select(VulnerabilityExposureModel, MachineModel.id)
            .join(
                SoftwareComponentModel,
                VulnerabilityExposureModel.software_component_id
                == SoftwareComponentModel.id,
            )
            .join(
                MachineModel,
                SoftwareComponentModel.machine_id == MachineModel.id,
            )
            .where(
                MachineModel.hostname == hostname,
                SoftwareComponentModel.detected_by == DEMO_DETECTED_BY,
            )
            .limit(1)
        ).first()
        if row is None:
            raise RuntimeError(
                f"Demo exposure for {hostname} not found. Run 'prepare' first."
            )
        exposure = row[0]
        machine_id = row[1]
        session.expunge(exposure)
        return exposure, machine_id


def _delete_demo_data(
    factory: sessionmaker[Session],
    organization_id: UUID,
) -> None:
    with factory() as session:
        machine_ids = list(
            session.scalars(
                select(MachineModel.id).where(
                    MachineModel.organization_id == organization_id,
                    MachineModel.hostname.in_(DEMO_HOSTNAMES),
                )
            )
        )
        if machine_ids:
            component_ids = list(
                session.scalars(
                    select(SoftwareComponentModel.id).where(
                        SoftwareComponentModel.machine_id.in_(machine_ids),
                        SoftwareComponentModel.detected_by == DEMO_DETECTED_BY,
                    )
                )
            )
            exposure_ids: list[UUID] = []
            if component_ids:
                exposure_ids = list(
                    session.scalars(
                        select(VulnerabilityExposureModel.id).where(
                            VulnerabilityExposureModel.software_component_id.in_(
                                component_ids
                            )
                        )
                    )
                )

            session.execute(
                delete(AlertModel).where(
                    AlertModel.organization_id == organization_id,
                    AlertModel.machine_id.in_(machine_ids),
                )
            )
            if exposure_ids:
                session.execute(
                    delete(VulnerabilityExposureModel).where(
                        VulnerabilityExposureModel.id.in_(exposure_ids)
                    )
                )
            if component_ids:
                session.execute(
                    delete(SoftwareComponentModel).where(
                        SoftwareComponentModel.id.in_(component_ids)
                    )
                )
            session.execute(
                delete(MachineModel).where(MachineModel.id.in_(machine_ids))
            )
        session.commit()


def _seed_machine_and_exposure(
    session: Session,
    *,
    organization_id: UUID,
    canonical_id: UUID,
    hostname: str,
    applicability: str,
    priority: str,
    version: str | None,
    now: datetime,
) -> tuple[UUID, UUID]:
    machine_id = uuid4()
    component_id = uuid4()
    exposure_id = uuid4()

    session.add(
        MachineModel(
            id=machine_id,
            organization_id=organization_id,
            machine_uid=uuid4(),
            hostname=hostname,
            os_name="Windows",
            os_version="11 Pro",
            architecture="x86_64",
            last_inventory_at=now,
            created_at=now,
            updated_at=now,
        )
    )
    session.flush()

    session.add(
        SoftwareComponentModel(
            id=component_id,
            machine_id=machine_id,
            component_type="package",
            name=DEMO_COMPONENT_NAME,
            normalized_name=DEMO_COMPONENT_NAME,
            version=version,
            vendor="Apache Software Foundation",
            normalized_vendor="apache software foundation",
            ecosystem="maven",
            external_id=None,
            scope="global",
            detected_by=DEMO_DETECTED_BY,
            created_at=now,
            updated_at=now,
        )
    )
    session.flush()

    session.add(
        VulnerabilityExposureModel(
            id=exposure_id,
            software_component_id=component_id,
            canonical_vulnerability_id=canonical_id,
            applicability_status=applicability,
            match_rule=(
                "demo_exact_version_match"
                if applicability == "confirmed"
                else "demo_missing_version_match"
            ),
            match_version="1.0.0",
            severity="CRITICAL",
            priority=priority,
            is_kev=False,
            first_detected_at=now,
            last_evaluated_at=now,
        )
    )
    return machine_id, exposure_id


def prepare(factory: sessionmaker[Session]) -> None:
    organization_id = _organization_id(factory)
    canonical_id = _canonical_vulnerability_id(factory)
    responsibles = _responsibles(factory, organization_id)
    if not responsibles:
        raise RuntimeError("The demo organization has no active security_responsible")

    _delete_demo_data(factory, organization_id)
    now = datetime.now(UTC)

    with factory() as session:
        confirmed_machine_id, confirmed_exposure_id = _seed_machine_and_exposure(
            session,
            organization_id=organization_id,
            canonical_id=canonical_id,
            hostname=CONFIRMED_HOSTNAME,
            applicability="confirmed",
            priority="HIGH",
            version=DEMO_COMPONENT_VERSION,
            now=now,
        )
        potential_machine_id, potential_exposure_id = _seed_machine_and_exposure(
            session,
            organization_id=organization_id,
            canonical_id=canonical_id,
            hostname=POTENTIAL_HOSTNAME,
            applicability="potential",
            priority="HIGH",
            version=None,
            now=now,
        )
        session.commit()

    print("FINAL_DEMO_PREPARED")
    print(f"organization_slug={_demo_slug()}")
    print(f"cve={_demo_cve()}")
    print(f"confirmed_machine={CONFIRMED_HOSTNAME}")
    print(f"confirmed_machine_id={confirmed_machine_id}")
    print(f"confirmed_exposure_id={confirmed_exposure_id}")
    print(f"potential_machine={POTENTIAL_HOSTNAME}")
    print(f"potential_machine_id={potential_machine_id}")
    print(f"potential_exposure_id={potential_exposure_id}")
    print("initial_state=confirmed HIGH non-KEV + potential HIGH non-KEV")
    print("Open Dashboard, Machines and Vulnerabilities before triggering an alert.")


def _evaluate(
    factory: sessionmaker[Session],
    *,
    organization_id: UUID,
    machine_id: UUID,
    transition: ExposureAlertTransition,
) -> AlertEvaluationResult:
    service = AlertEvaluationService(
        unit_of_work=SqlAlchemyAlertUnitOfWork(
            session_factory=factory,  # type: ignore[arg-type]
        ),
        notification_port=load_notification_port(),
    )
    return service.evaluate(
        organization_id=organization_id,
        machine_id=machine_id,
        transitions=(transition,),
        evaluated_at=datetime.now(UTC),
    )


def _print_result(name: str, result: AlertEvaluationResult) -> None:
    print(f"SCENARIO={name}")
    print(f"candidate_events={result.candidate_event_count}")
    print(f"created_alerts={result.created_alert_count}")
    print(f"sent_notifications={result.sent_notification_count}")
    print(f"failed_notifications={result.failed_notification_count}")
    for alert in result.created_alerts:
        print(f"alert_id={alert.id}")
        print(f"alert_type={alert.alert_type}")


def trigger_priority(factory: sessionmaker[Session]) -> None:
    organization_id = _organization_id(factory)
    exposure, machine_id = _find_demo_exposure(factory, CONFIRMED_HOSTNAME)
    if exposure.priority != "HIGH":
        raise RuntimeError("Confirmed demo exposure must be HIGH. Run 'prepare' first.")

    now = datetime.now(UTC)
    with factory() as session:
        managed = session.get(VulnerabilityExposureModel, exposure.id)
        if managed is None:
            raise RuntimeError("Demo exposure disappeared")
        managed.priority = "CRITICAL"
        managed.last_evaluated_at = now
        session.commit()

    result = _evaluate(
        factory,
        organization_id=organization_id,
        machine_id=machine_id,
        transition=ExposureAlertTransition(
            exposure_id=exposure.id,
            canonical_vulnerability_id=exposure.canonical_vulnerability_id,
            applicability_status="confirmed",
            is_new_exposure=False,
            previous_priority="HIGH",
            current_priority="CRITICAL",
            previous_is_kev=False,
            current_is_kev=False,
        ),
    )
    _print_result("priority_high_to_critical", result)


def trigger_kev(factory: sessionmaker[Session]) -> None:
    organization_id = _organization_id(factory)
    exposure, machine_id = _find_demo_exposure(factory, CONFIRMED_HOSTNAME)
    if exposure.is_kev:
        raise RuntimeError("Confirmed demo exposure is already KEV. Run 'prepare' first.")

    previous_priority = exposure.priority
    now = datetime.now(UTC)
    with factory() as session:
        managed = session.get(VulnerabilityExposureModel, exposure.id)
        if managed is None:
            raise RuntimeError("Demo exposure disappeared")
        managed.is_kev = True
        managed.last_evaluated_at = now
        session.commit()

    result = _evaluate(
        factory,
        organization_id=organization_id,
        machine_id=machine_id,
        transition=ExposureAlertTransition(
            exposure_id=exposure.id,
            canonical_vulnerability_id=exposure.canonical_vulnerability_id,
            applicability_status="confirmed",
            is_new_exposure=False,
            previous_priority=previous_priority,
            current_priority=previous_priority,
            previous_is_kev=False,
            current_is_kev=True,
        ),
    )
    _print_result("confirmed_entered_kev", result)


def trigger_new_critical(factory: sessionmaker[Session]) -> None:
    organization_id = _organization_id(factory)
    canonical_id = _canonical_vulnerability_id(factory)
    now = datetime.now(UTC)

    with factory() as session:
        existing = session.scalar(
            select(MachineModel.id).where(
                MachineModel.organization_id == organization_id,
                MachineModel.hostname == NEW_CRITICAL_HOSTNAME,
            )
        )
        if existing is not None:
            raise RuntimeError("New-critical demo already exists. Run 'reset' then 'prepare'.")

        machine_id, exposure_id = _seed_machine_and_exposure(
            session,
            organization_id=organization_id,
            canonical_id=canonical_id,
            hostname=NEW_CRITICAL_HOSTNAME,
            applicability="confirmed",
            priority="CRITICAL",
            version=DEMO_COMPONENT_VERSION,
            now=now,
        )
        session.commit()

    result = _evaluate(
        factory,
        organization_id=organization_id,
        machine_id=machine_id,
        transition=ExposureAlertTransition(
            exposure_id=exposure_id,
            canonical_vulnerability_id=canonical_id,
            applicability_status="confirmed",
            is_new_exposure=True,
            previous_priority=None,
            current_priority="CRITICAL",
            previous_is_kev=None,
            current_is_kev=False,
        ),
    )
    _print_result("new_confirmed_critical", result)


def potential_no_alert(factory: sessionmaker[Session]) -> None:
    organization_id = _organization_id(factory)
    exposure, machine_id = _find_demo_exposure(factory, POTENTIAL_HOSTNAME)
    previous_priority = exposure.priority

    now = datetime.now(UTC)
    with factory() as session:
        managed = session.get(VulnerabilityExposureModel, exposure.id)
        if managed is None:
            raise RuntimeError("Potential demo exposure disappeared")
        managed.priority = "CRITICAL"
        managed.last_evaluated_at = now
        session.commit()

    result = _evaluate(
        factory,
        organization_id=organization_id,
        machine_id=machine_id,
        transition=ExposureAlertTransition(
            exposure_id=exposure.id,
            canonical_vulnerability_id=exposure.canonical_vulnerability_id,
            applicability_status="potential",
            is_new_exposure=False,
            previous_priority=previous_priority,
            current_priority="CRITICAL",
            previous_is_kev=False,
            current_is_kev=False,
        ),
    )
    _print_result("potential_critical_no_alert", result)
    if result.created_alert_count != 0:
        raise RuntimeError("Potential exposure unexpectedly created an alert")


def replay_priority(factory: sessionmaker[Session]) -> None:
    organization_id = _organization_id(factory)
    exposure, machine_id = _find_demo_exposure(factory, CONFIRMED_HOSTNAME)
    if exposure.priority != "CRITICAL":
        raise RuntimeError("Run 'trigger-priority' before 'replay-priority'.")

    result = _evaluate(
        factory,
        organization_id=organization_id,
        machine_id=machine_id,
        transition=ExposureAlertTransition(
            exposure_id=exposure.id,
            canonical_vulnerability_id=exposure.canonical_vulnerability_id,
            applicability_status="confirmed",
            is_new_exposure=False,
            previous_priority="HIGH",
            current_priority="CRITICAL",
            previous_is_kev=False,
            current_is_kev=False,
        ),
    )
    _print_result("dedup_replay_priority", result)
    if result.created_alert_count != 0:
        raise RuntimeError("Duplicate replay unexpectedly created another alert")


def status(factory: sessionmaker[Session]) -> None:
    organization_id = _organization_id(factory)
    responsibles = _responsibles(factory, organization_id)
    print(f"organization_slug={_demo_slug()}")
    print(f"cve={_demo_cve()}")
    print(f"notification_backend={os.getenv('TIP_NOTIFICATION_BACKEND', 'disabled')}")
    print("security_responsibles=" + ", ".join(email for _, email in responsibles))

    with factory() as session:
        rows = session.execute(
            select(
                MachineModel.hostname,
                VulnerabilityExposureModel.id,
                VulnerabilityExposureModel.applicability_status,
                VulnerabilityExposureModel.priority,
                VulnerabilityExposureModel.is_kev,
            )
            .join(
                SoftwareComponentModel,
                SoftwareComponentModel.machine_id == MachineModel.id,
            )
            .join(
                VulnerabilityExposureModel,
                VulnerabilityExposureModel.software_component_id
                == SoftwareComponentModel.id,
            )
            .where(
                MachineModel.organization_id == organization_id,
                MachineModel.hostname.in_(DEMO_HOSTNAMES),
                SoftwareComponentModel.detected_by == DEMO_DETECTED_BY,
            )
            .order_by(MachineModel.hostname)
        ).all()

        for row in rows:
            print(
                "exposure="
                f"{row.hostname} id={row.id} "
                f"applicability={row.applicability_status} "
                f"priority={row.priority} kev={row.is_kev}"
            )

        alerts = session.execute(
            select(
                AlertModel.id,
                AlertModel.alert_type,
                AlertModel.status,
                AlertModel.sent_at,
                MachineModel.hostname,
            )
            .join(MachineModel, AlertModel.machine_id == MachineModel.id)
            .where(
                AlertModel.organization_id == organization_id,
                MachineModel.hostname.in_(DEMO_HOSTNAMES),
            )
            .order_by(AlertModel.created_at)
        ).all()
        for row in alerts:
            print(
                "alert="
                f"{row.id} type={row.alert_type} status={row.status} "
                f"machine={row.hostname} sent_at={row.sent_at}"
            )


def reset(factory: sessionmaker[Session]) -> None:
    organization_id = _organization_id(factory)
    _delete_demo_data(factory, organization_id)
    print("FINAL_DEMO_RESET_OK")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Deterministic final PFA demo scenarios using real platform services."
    )
    parser.add_argument(
        "command",
        choices=(
            "prepare",
            "status",
            "trigger-priority",
            "trigger-kev",
            "trigger-new-critical",
            "potential-no-alert",
            "replay-priority",
            "reset",
        ),
    )
    args = parser.parse_args()

    factory, engine = _session_factory()
    try:
        commands = {
            "prepare": prepare,
            "status": status,
            "trigger-priority": trigger_priority,
            "trigger-kev": trigger_kev,
            "trigger-new-critical": trigger_new_critical,
            "potential-no-alert": potential_no_alert,
            "replay-priority": replay_priority,
            "reset": reset,
        }
        commands[args.command](factory)
    finally:
        engine.dispose()  # type: ignore[attr-defined]


if __name__ == "__main__":
    main()
