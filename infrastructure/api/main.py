from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI

from application.services.analyze_url_service import (
    AnalyzeURLService,
)
from application.services.get_alert_detail_service import (
    GetAlertDetailService,
)
from application.services.get_dashboard_summary_service import (
    GetDashboardSummaryService,
)
from application.services.get_machine_detail_service import (
    GetMachineDetailService,
)
from application.services.get_vulnerability_detail_service import (
    GetVulnerabilityDetailService,
)
from application.services.import_and_process_machine_inventory_service import (
    ImportAndProcessMachineInventoryService,
)
from application.services.import_machine_inventory_service import (
    ImportMachineInventoryService,
)
from application.services.list_alerts_service import (
    ListAlertsService,
)
from application.services.list_machines_service import (
    ListMachinesService,
)
from application.services.list_software_service import (
    ListSoftwareService,
)
from application.services.list_vulnerabilities_service import (
    ListVulnerabilitiesService,
)
from infrastructure.adapters.outbound.joblib_url_threat_classifier import (
    JoblibURLThreatClassifier,
)
from infrastructure.api.app import (
    create_app,
)
from infrastructure.api.machine_credentials import (
    load_machine_api_key_authenticator,
)
from infrastructure.bootstrap.machine_vulnerability_processing import (
    build_process_machine_vulnerabilities_service,
)
from infrastructure.notifications.disabled_notification_adapter import (
    DisabledNotificationAdapter,
)
from infrastructure.persistence.sqlalchemy.asset_engine import (
    create_asset_engine,
)
from infrastructure.persistence.sqlalchemy.asset_inventory_unit_of_work import (
    SqlAlchemyAssetInventoryUnitOfWork,
)
from infrastructure.persistence.sqlalchemy.readers.alert_read_repository import (
    SqlAlchemyAlertReadRepository,
)
from infrastructure.persistence.sqlalchemy.readers.dashboard_read_repository import (
    SqlAlchemyDashboardReadRepository,
)
from infrastructure.persistence.sqlalchemy.readers.machine_read_repository import (
    SqlAlchemyMachineReadRepository,
)
from infrastructure.persistence.sqlalchemy.readers.software_read_repository import (
    SqlAlchemySoftwareReadRepository,
)
from infrastructure.persistence.sqlalchemy.readers.vulnerability_read_repository import (
    SqlAlchemyVulnerabilityReadRepository,
)
from infrastructure.persistence.sqlalchemy.session import (
    create_session_factory,
)


REPOSITORY_ROOT = (
    Path(__file__)
    .resolve()
    .parents[2]
)


URL_MODEL_PATH = (
    REPOSITORY_ROOT
    / "artifacts"
    / "ml"
    / "models"
    / "url_multiclass_hgb_v3_hardened.joblib"
)


URL_MODEL_METADATA_PATH = (
    REPOSITORY_ROOT
    / "artifacts"
    / "ml"
    / "models"
    / "url_multiclass_hgb_v3_hardened.metadata.json"
)


def build_app() -> FastAPI:
    engine = create_asset_engine()

    session_factory = (
        create_session_factory(
            engine
        )
    )

    # =========================================================
    # Inventaire + traitement automatique des vulnérabilités
    # =========================================================

    inventory_unit_of_work = (
        SqlAlchemyAssetInventoryUnitOfWork(
            session_factory
        )
    )

    base_import_service = (
        ImportMachineInventoryService(
            unit_of_work=(
                inventory_unit_of_work
            )
        )
    )

    # En runtime actuel, la livraison réelle Gmail
    # n'est pas encore activée.
    #
    # Le DisabledNotificationAdapter garantit qu'une
    # notification non réellement envoyée ne sera jamais
    # marquée comme "sent".
    notification_port = (
        DisabledNotificationAdapter()
    )

    vulnerability_processing_service = (
        build_process_machine_vulnerabilities_service(
            session_factory=(
                session_factory
            ),
            notification_port=(
                notification_port
            ),
        )
    )

    inventory_service = (
        ImportAndProcessMachineInventoryService(
            import_service=(
                base_import_service
            ),
            vulnerability_processing_service=(
                vulnerability_processing_service
            ),
        )
    )

    # =========================================================
    # Auth machine V1
    # =========================================================

    authenticator = (
        load_machine_api_key_authenticator()
    )

    # =========================================================
    # Analyse URL
    # =========================================================

    url_classifier = (
        JoblibURLThreatClassifier(
            model_path=(
                URL_MODEL_PATH
            ),
            metadata_path=(
                URL_MODEL_METADATA_PATH
            ),
        )
    )

    analyze_url_service = (
        AnalyzeURLService(
            classifier=(
                url_classifier
            )
        )
    )

    # =========================================================
    # Dashboard
    # =========================================================

    dashboard_repository = (
        SqlAlchemyDashboardReadRepository(
            session_factory
        )
    )

    dashboard_service = (
        GetDashboardSummaryService(
            repository=(
                dashboard_repository
            )
        )
    )

    # =========================================================
    # Machines
    # =========================================================

    machine_repository = (
        SqlAlchemyMachineReadRepository(
            session_factory
        )
    )

    machines_service = (
        ListMachinesService(
            repository=(
                machine_repository
            )
        )
    )

    machine_detail_service = (
        GetMachineDetailService(
            repository=(
                machine_repository
            )
        )
    )

    # =========================================================
    # Logiciels
    # =========================================================

    software_repository = (
        SqlAlchemySoftwareReadRepository(
            session_factory
        )
    )

    software_service = (
        ListSoftwareService(
            repository=(
                software_repository
            )
        )
    )

    # =========================================================
    # Vulnérabilités
    # =========================================================

    vulnerability_repository = (
        SqlAlchemyVulnerabilityReadRepository(
            session_factory
        )
    )

    vulnerabilities_service = (
        ListVulnerabilitiesService(
            repository=(
                vulnerability_repository
            )
        )
    )

    vulnerability_detail_service = (
        GetVulnerabilityDetailService(
            repository=(
                vulnerability_repository
            )
        )
    )

    # =========================================================
    # Alertes
    # =========================================================

    alert_repository = (
        SqlAlchemyAlertReadRepository(
            session_factory
        )
    )

    alerts_service = (
        ListAlertsService(
            repository=(
                alert_repository
            )
        )
    )

    alert_detail_service = (
        GetAlertDetailService(
            repository=(
                alert_repository
            )
        )
    )

    # =========================================================
    # FastAPI
    # =========================================================

    app = create_app(
        import_service=(
            inventory_service
        ),  # type: ignore[arg-type]
        authenticator=(
            authenticator
        ),
        analyze_url_service=(
            analyze_url_service
        ),
        dashboard_service=(
            dashboard_service
        ),
        machines_service=(
            machines_service
        ),
        machine_detail_service=(
            machine_detail_service
        ),
        software_service=(
            software_service
        ),
        vulnerabilities_service=(
            vulnerabilities_service
        ),
        vulnerability_detail_service=(
            vulnerability_detail_service
        ),
        alerts_service=(
            alerts_service
        ),
        alert_detail_service=(
            alert_detail_service
        ),
    )

    app.state.asset_engine = (
        engine
    )

    return app


app = build_app()