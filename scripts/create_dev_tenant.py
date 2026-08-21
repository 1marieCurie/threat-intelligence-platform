from __future__ import annotations

import os
import sys
from datetime import (
    UTC,
    datetime,
)
from pathlib import Path
from uuid import uuid4


PROJECT_ROOT = (
    Path(__file__)
    .resolve()
    .parents[1]
)

project_root_value = str(
    PROJECT_ROOT
)

if project_root_value not in sys.path:
    sys.path.insert(
        0,
        project_root_value,
    )


from sqlalchemy import select
from sqlalchemy.orm import Session

from application.security.password_hasher import (
    PasswordHasher,
)
from infrastructure.persistence.models.assets import (
    OrganizationModel,
    UserAccountModel,
)
from infrastructure.persistence.sqlalchemy.asset_engine import (
    create_asset_engine,
)
from infrastructure.persistence.sqlalchemy.session import (
    create_session_factory,
)


DEV_ORGANIZATION_NAME = (
    "Threat Intelligence Development"
)

DEV_STAFF_EMAIL = (
    "staff@tip.local"
)

DEV_STAFF_DISPLAY_NAME = (
    "Development Staff"
)

DEV_SECURITY_EMAIL = (
    "security@tip.local"
)

DEV_SECURITY_DISPLAY_NAME = (
    "Development Security Responsible"
)


def _require_password(
    variable_name: str,
) -> str:
    value = os.environ.get(
        variable_name
    )

    if value is None:
        raise RuntimeError(
            f"{variable_name} is not defined"
        )

    value = value.strip()

    if len(value) < 8:
        raise RuntimeError(
            f"{variable_name} must contain "
            "at least 8 characters"
        )

    return value


def _get_or_create_organization(
    *,
    session: Session,
) -> OrganizationModel:
    organization = (
        session.scalar(
            select(
                OrganizationModel
            ).where(
                OrganizationModel.name
                == DEV_ORGANIZATION_NAME
            )
        )
    )

    if organization is not None:
        print(
            "Development organization "
            "already exists."
        )

        return organization

    organization = OrganizationModel(
        id=uuid4(),
        name=DEV_ORGANIZATION_NAME,
        is_active=True,
        created_at=datetime.now(
            UTC
        ),
    )

    session.add(
        organization
    )

    session.flush()

    print(
        "Development organization created."
    )

    return organization


def _upsert_user(
    *,
    session: Session,
    organization_id,
    email: str,
    display_name: str,
    role: str,
    password: str,
    password_hasher: PasswordHasher,
) -> UserAccountModel:
    user = (
        session.scalar(
            select(
                UserAccountModel
            ).where(
                UserAccountModel.organization_id
                == organization_id,
                UserAccountModel.email
                == email,
            )
        )
    )

    password_hash = (
        password_hasher.hash_password(
            password
        )
    )

    if user is None:
        user = UserAccountModel(
            id=uuid4(),
            organization_id=(
                organization_id
            ),
            email=email,
            display_name=(
                display_name
            ),
            password_hash=(
                password_hash
            ),
            role=role,
            is_active=True,
            created_at=datetime.now(
                UTC
            ),
        )

        session.add(
            user
        )

        print(
            f"Development user {email} "
            "created."
        )

        return user

    user.display_name = (
        display_name
    )

    user.role = role
    user.is_active = True

    user.password_hash = (
        password_hash
    )

    print(
        f"Development user {email} "
        "updated."
    )

    return user


def main() -> None:
    staff_password = (
        _require_password(
            "TIP_DEV_STAFF_PASSWORD"
        )
    )

    security_password = (
        _require_password(
            "TIP_DEV_SECURITY_PASSWORD"
        )
    )

    password_hasher = (
        PasswordHasher()
    )

    engine = (
        create_asset_engine()
    )

    session_factory = (
        create_session_factory(
            engine
        )
    )

    try:
        with session_factory() as session:
            organization = (
                _get_or_create_organization(
                    session=session
                )
            )

            staff_user = (
                _upsert_user(
                    session=session,
                    organization_id=(
                        organization.id
                    ),
                    email=(
                        DEV_STAFF_EMAIL
                    ),
                    display_name=(
                        DEV_STAFF_DISPLAY_NAME
                    ),
                    role="staff",
                    password=(
                        staff_password
                    ),
                    password_hasher=(
                        password_hasher
                    ),
                )
            )

            security_user = (
                _upsert_user(
                    session=session,
                    organization_id=(
                        organization.id
                    ),
                    email=(
                        DEV_SECURITY_EMAIL
                    ),
                    display_name=(
                        DEV_SECURITY_DISPLAY_NAME
                    ),
                    role=(
                        "security_responsible"
                    ),
                    password=(
                        security_password
                    ),
                    password_hasher=(
                        password_hasher
                    ),
                )
            )

            session.commit()

            print()
            print(
                "Development authentication "
                "tenant ready."
            )

            print(
                "organization_id="
                f"{organization.id}"
            )

            print(
                "staff_user_id="
                f"{staff_user.id}"
            )

            print(
                "staff_email="
                f"{staff_user.email}"
            )

            print(
                "security_user_id="
                f"{security_user.id}"
            )

            print(
                "security_email="
                f"{security_user.email}"
            )

    finally:
        engine.dispose()


if __name__ == "__main__":
    main()