from __future__ import annotations

import sys
from datetime import (
    UTC,
    datetime,
)
from pathlib import Path
from uuid import uuid4


# ============================================================
# Racine du projet
# ============================================================
#
# Permet d'exécuter directement :
#
#     python scripts/create_dev_tenant.py
#
# tout en conservant les imports absolus du projet.
# ============================================================

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

DEV_SECURITY_EMAIL = (
    "security.dev@example.test"
)

DEV_SECURITY_DISPLAY_NAME = (
    "Development Security Responsible"
)


def main() -> None:
    engine = create_asset_engine()

    session_factory = (
        create_session_factory(
            engine
        )
    )

    try:
        with session_factory() as session:
            # =================================================
            # Organisation de développement
            # =================================================

            existing_organization = (
                session.execute(
                    select(
                        OrganizationModel
                    ).where(
                        OrganizationModel.name
                        == DEV_ORGANIZATION_NAME
                    )
                )
                .scalar_one_or_none()
            )

            if existing_organization is None:
                organization = (
                    OrganizationModel(
                        id=uuid4(),
                        name=(
                            DEV_ORGANIZATION_NAME
                        ),
                        is_active=True,
                        created_at=(
                            datetime.now(
                                UTC
                            )
                        ),
                    )
                )

                session.add(
                    organization
                )

                session.flush()

                print(
                    "Development organization "
                    "created."
                )

            else:
                organization = (
                    existing_organization
                )

                print(
                    "Development organization "
                    "already exists."
                )

            # =================================================
            # Responsable sécurité de développement
            # =================================================

            existing_user = (
                session.execute(
                    select(
                        UserAccountModel
                    ).where(
                        UserAccountModel
                        .organization_id
                        == organization.id,
                        UserAccountModel.email
                        == DEV_SECURITY_EMAIL,
                    )
                )
                .scalar_one_or_none()
            )

            if existing_user is None:
                user = (
                    UserAccountModel(
                        id=uuid4(),
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
                        is_active=True,
                        created_at=(
                            datetime.now(
                                UTC
                            )
                        ),
                    )
                )

                session.add(
                    user
                )

                print(
                    "Development security "
                    "responsible created."
                )

            else:
                user = existing_user

                print(
                    "Development security "
                    "responsible already exists."
                )

            # =================================================
            # Persistance
            # =================================================

            session.commit()

            # =================================================
            # Informations utiles au frontend dev
            # =================================================

            print()
            print(
                "organization_id="
                f"{organization.id}"
            )

            print(
                "security_user_id="
                f"{user.id}"
            )

            print(
                "security_email="
                f"{user.email}"
            )

    finally:
        engine.dispose()


if __name__ == "__main__":
    main()