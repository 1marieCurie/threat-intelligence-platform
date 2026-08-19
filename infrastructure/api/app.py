from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import (
    CORSMiddleware,
)

from application.security.machine_api_key_authenticator import (
    MachineApiKeyAuthenticator,
)
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
from infrastructure.api.dashboard_router import (
    create_dashboard_router,
)
from infrastructure.api.inventory_router import (
    create_inventory_router,
)
from infrastructure.api.machines_router import (
    create_machines_router,
)
from infrastructure.api.software_router import (
    create_software_router,
)
from infrastructure.api.url_analysis_router import (
    create_url_analysis_router,
)


DEV_FRONTEND_ORIGINS = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
]


def create_app(
    *,
    import_service: (
        ImportMachineInventoryService
    ),
    authenticator: (
        MachineApiKeyAuthenticator
    ),
    analyze_url_service: (
        AnalyzeURLService | None
    ) = None,
    dashboard_service: (
        GetDashboardSummaryService | None
    ) = None,
    machines_service: (
        ListMachinesService | None
    ) = None,
    machine_detail_service: (
        GetMachineDetailService | None
    ) = None,
    software_service: (
        ListSoftwareService | None
    ) = None,
) -> FastAPI:
    if import_service is None:
        raise ValueError(
            "import_service must not be None"
        )

    if authenticator is None:
        raise ValueError(
            "authenticator must not be None"
        )

    app = FastAPI(
        title="Threat Intelligence Platform",
        version="0.1.0",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=(
            DEV_FRONTEND_ORIGINS
        ),
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(
        create_inventory_router(
            import_service=(
                import_service
            ),
            authenticator=(
                authenticator
            ),
        )
    )

    if analyze_url_service is not None:
        app.include_router(
            create_url_analysis_router(
                analyze_url_service=(
                    analyze_url_service
                )
            )
        )

    if dashboard_service is not None:
        app.include_router(
            create_dashboard_router(
                service=(
                    dashboard_service
                )
            )
        )

    if (
        machines_service is not None
        and machine_detail_service
        is not None
    ):
        app.include_router(
            create_machines_router(
                list_service=(
                    machines_service
                ),
                detail_service=(
                    machine_detail_service
                ),
            )
        )

    if software_service is not None:
        app.include_router(
            create_software_router(
                service=(
                    software_service
                )
            )
        )

    @app.get("/health")
    def health() -> dict[
        str,
        str,
    ]:
        return {
            "status": "ok",
        }

    return app