from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI

from application.services.analyze_url_service import (
    AnalyzeURLService,
)
from application.services.get_dashboard_summary_service import (
    GetDashboardSummaryService,
)
from application.services.get_machine_detail_service import (
    GetMachineDetailService,
)
from application.services.import_machine_inventory_service import (
    ImportMachineInventoryService,
)
from application.services.list_machines_service import (
    ListMachinesService,
)
from application.services.list_software_service import (
    ListSoftwareService,
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
from infrastructure.persistence.sqlalchemy.asset_engine import (
    create_asset_engine,
)
from infrastructure.persistence.sqlalchemy.asset_inventory_unit_of_work import (
    SqlAlchemyAssetInventoryUnitOfWork,
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

    unit_of_work = (
        SqlAlchemyAssetInventoryUnitOfWork(
            session_factory
        )
    )

    import_service = (
        ImportMachineInventoryService(
            unit_of_work=unit_of_work
        )
    )

    authenticator = (
        load_machine_api_key_authenticator()
    )

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

    app = create_app(
        import_service=(
            import_service
        ),
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
    )

    app.state.asset_engine = (
        engine
    )

    return app


app = build_app()