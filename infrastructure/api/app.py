from __future__ import annotations

from fastapi import FastAPI

from application.security.machine_api_key_authenticator import (
    MachineApiKeyAuthenticator,
)
from application.services.import_machine_inventory_service import (
    ImportMachineInventoryService,
)
from infrastructure.api.inventory_router import (
    create_inventory_router,
)


def create_app(
    *,
    import_service: (
        ImportMachineInventoryService
    ),
    authenticator: (
        MachineApiKeyAuthenticator
    ),
) -> FastAPI:
    app = FastAPI(
        title=(
            "Threat Intelligence Platform API"
        ),
        version="0.1.0",
    )

    app.include_router(
        create_inventory_router(
            import_service=import_service,
            authenticator=authenticator,
        )
    )

    @app.get(
        "/health",
        tags=["system"],
    )
    def health() -> dict[str, str]:
        return {
            "status": "ok",
        }

    return app