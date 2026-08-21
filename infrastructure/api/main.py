from __future__ import annotations

import os
from pathlib import Path

from fastapi import FastAPI

from application.security.access_token_codec import (
    AccessTokenCodec,
)
from application.security.password_hasher import (
    PasswordHasher,
)
from application.security.refresh_tokens import (
    RefreshTokenManager,
)
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
from application.services.user_authentication_service import (
    UserAuthenticationService,
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
from infrastructure.persistence.sqlalchemy.authentication_unit_of_work import (
    SqlAlchemyAuthenticationUnitOfWork,
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


def _require_environment_value(
    name: str,
) -> str:
    value = os.environ.get(
        name
    )

    if value is None:
        raise RuntimeError(
            f"{name} is not defined"
        )

    normalized = value.strip()

    if not normalized:
        raise RuntimeError(
            f"{name} must not be empty"
        )

    if normalized == "CHANGE_ME":
        raise RuntimeError(
            f"{name} must be configured"
        )

    return normalized


def _read_positive_integer(
    name: str,
    *,
    default: int,
) -> int:
    raw_value = os.environ.get(
        name
    )

    if raw_value is None:
        return default

    try:
        value = int(
            raw_value.strip()
        )

    except (
        TypeError,
        ValueError,
    ) as error:
        raise RuntimeError(
            f"{name} must be an integer"
        ) from error

    if value <= 0:
        raise RuntimeError(
            f"{name} must be positive"
        )

    return value


def _read_boolean(
    name: str,
    *,
    default: bool,
) -> bool:
    raw_value = os.environ.get(
        name
    )

    if raw_value is None:
        return default

    normalized = (
        raw_value
        .strip()
        .lower()
    )

    if normalized in {
        "1",
        "true",
        "yes",
        "on",
    }:
        return True

    if normalized in {
        "0",
        "false",
        "no",
        "off",
    }:
        return False

    raise RuntimeError(
        f"{name} must be a boolean"
    )


def build_app() -> FastAPI:
    engine = (
        create_asset_engine()
    )

    session_factory = (
        create_session_factory(
            engine
        )
    )

    # =========================================================
    # Authentification utilisateurs
    # =========================================================

    jwt_secret = (
        _require_environment_value(
            "TIP_AUTH_JWT_SECRET"
        )
    )

    auth_issuer = (
        _require_environment_value(
            "TIP_AUTH_ISSUER"
        )
    )

    auth_audience = (
        _require_environment_value(
            "TIP_AUTH_AUDIENCE"
        )
    )

    access_token_ttl_seconds = (
        _read_positive_integer(
            (
                "TIP_AUTH_ACCESS_TOKEN_"
                "TTL_SECONDS"
            ),
            default=900,
        )
    )

    refresh_token_ttl_seconds = (
        _read_positive_integer(
            (
                "TIP_AUTH_REFRESH_TOKEN_"
                "TTL_SECONDS"
            ),
            default=(
                30 * 24 * 60 * 60
            ),
        )
    )

    auth_cookie_secure = (
        _read_boolean(
            "TIP_AUTH_COOKIE_SECURE",
            default=False,
        )
    )

    authentication_unit_of_work = (
        SqlAlchemyAuthenticationUnitOfWork(
            session_factory
        )
    )

    password_hasher = (
        PasswordHasher()
    )

    refresh_token_manager = (
        RefreshTokenManager()
    )

    access_token_codec = (
        AccessTokenCodec(
            secret=jwt_secret,
            issuer=auth_issuer,
            audience=auth_audience,
            ttl_seconds=(
                access_token_ttl_seconds
            ),
        )
    )

    authentication_service = (
        UserAuthenticationService(
            unit_of_work=(
                authentication_unit_of_work
            ),
            password_hasher=(
                password_hasher
            ),
            access_token_codec=(
                access_token_codec
            ),
            refresh_token_manager=(
                refresh_token_manager
            ),
            access_token_ttl_seconds=(
                access_token_ttl_seconds
            ),
            refresh_token_ttl_seconds=(
                refresh_token_ttl_seconds
            ),
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
    # Auth machine
    # =========================================================

    machine_authenticator = (
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
            machine_authenticator
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
        authentication_service=(
            authentication_service
        ),
        auth_refresh_token_ttl_seconds=(
            refresh_token_ttl_seconds
        ),
        auth_cookie_secure=(
            auth_cookie_secure
        ),
    )

    app.state.asset_engine = (
        engine
    )

    return app


app = build_app()