from __future__ import annotations

from pathlib import Path

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    status,
)
from fastapi.responses import (
    PlainTextResponse,
)

from domain.user_account import (
    UserAccount,
)
from infrastructure.api.auth_dependencies import (
    require_security_responsible_user,
)


REPOSITORY_ROOT = (
    Path(__file__)
    .resolve()
    .parents[2]
)

WINDOWS_INVENTORY_SCRIPT_PATH = (
    REPOSITORY_ROOT
    / "scripts"
    / "agent"
    / "windows"
    / "collect_inventory.ps1"
)


def create_inventory_agent_router(
) -> APIRouter:
    router = APIRouter(
        prefix="/api/v1",
        tags=["inventory-agent"],
    )

    @router.get(
        "/inventory-agent/windows/script",
        response_class=PlainTextResponse,
        status_code=status.HTTP_200_OK,
    )
    def get_windows_inventory_script(
        _: UserAccount = Depends(
            require_security_responsible_user
        ),
    ) -> PlainTextResponse:
        try:
            content = (
                WINDOWS_INVENTORY_SCRIPT_PATH
                .read_text(
                    encoding="utf-8"
                )
            )

        except OSError as error:
            raise HTTPException(
                status_code=(
                    status
                    .HTTP_503_SERVICE_UNAVAILABLE
                ),
                detail=(
                    "Windows inventory script "
                    "is temporarily unavailable"
                ),
            ) from error

        return PlainTextResponse(
            content=content,
            media_type=(
                "text/plain; charset=utf-8"
            ),
        )

    return router