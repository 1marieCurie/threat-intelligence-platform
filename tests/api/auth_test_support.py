from __future__ import annotations

from datetime import (
    UTC,
    datetime,
)
from uuid import (
    UUID,
    uuid4,
)

from fastapi import FastAPI

from domain.user_account import (
    UserAccount,
)
from infrastructure.api.auth_dependencies import (
    require_authenticated_user,
    require_security_organization_id,
    require_security_responsible_user,
)


NOW = datetime(
    2026,
    8,
    21,
    21,
    0,
    tzinfo=UTC,
)


def build_user(
    *,
    role: str,
    organization_id: UUID,
) -> UserAccount:
    return UserAccount(
        id=uuid4(),
        organization_id=(
            organization_id
        ),
        email=(
            "security@tip.local"
            if role
            == "security_responsible"
            else "staff@tip.local"
        ),
        display_name="Test User",
        role=role,
        is_active=True,
        created_at=NOW,
    )


def allow_security_user(
    app: FastAPI,
    *,
    organization_id: UUID,
) -> UserAccount:
    user = build_user(
        role="security_responsible",
        organization_id=organization_id,
    )

    app.dependency_overrides[
        require_security_organization_id
    ] = lambda: organization_id

    app.dependency_overrides[
        require_security_responsible_user
    ] = lambda: user

    app.dependency_overrides[
        require_authenticated_user
    ] = lambda: user

    return user


def allow_staff_user(
    app: FastAPI,
    *,
    organization_id: UUID,
) -> UserAccount:
    user = build_user(
        role="staff",
        organization_id=organization_id,
    )

    app.dependency_overrides[
        require_authenticated_user
    ] = lambda: user

    return user