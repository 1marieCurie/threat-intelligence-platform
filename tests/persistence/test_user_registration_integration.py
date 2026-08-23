from __future__ import annotations

import os
from collections.abc import Iterator
from datetime import (
    UTC,
    datetime,
)
from pathlib import Path
from uuid import (
    UUID,
    uuid4,
)

import pytest
from dotenv import load_dotenv
from sqlalchemy import (
    create_engine,
    delete,
    select,
    text,
)
from sqlalchemy.engine import Connection
from sqlalchemy.orm import (
    Session,
    sessionmaker,
)
from sqlalchemy.pool import NullPool

from application.ports.outbound.user_registration_repository import (
    UserRegistrationConflictError,
)
from application.security.password_hasher import (
    PasswordHasher,
)
from application.services.user_registration_service import (
    UserRegistrationService,
)
from domain.organization import Organization
from domain.user_account import UserAccount
from infrastructure.persistence.models.assets import (
    OrganizationModel,
    UserAccountModel,
)
from infrastructure.persistence.sqlalchemy.user_registration_unit_of_work import (
    SqlAlchemyUserRegistrationUnitOfWork,
)


PROJECT_ROOT = (
    Path(__file__)
    .resolve()
    .parents[2]
)

load_dotenv(
    dotenv_path=(
        PROJECT_ROOT / ".env"
    ),
    override=False,
)

pytestmark = pytest.mark.integration


SessionFactory = sessionmaker[
    Session
]


@pytest.fixture
def registration_database(
) -> Iterator[
    tuple[
        Connection,
        SessionFactory,
    ]
]:
    database_url = os.environ.get(
        "MIGRATION_DATABASE_URL"
    )

    if not database_url:
        raise RuntimeError(
            (
                "MIGRATION_DATABASE_URL "
                "is not defined"
            )
        )

    engine = create_engine(
        database_url,
        pool_pre_ping=True,
        poolclass=NullPool,
        future=True,
    )

    connection = engine.connect()

    connection.execute(
        text(
            "SET ROLE threat_intel_owner"
        )
    )
    connection.commit()

    session_factory = sessionmaker(
        bind=connection,
        class_=Session,
        autoflush=False,
        expire_on_commit=False,
    )

    try:
        yield (
            connection,
            session_factory,
        )

    finally:
        try:
            connection.execute(
                text(
                    "RESET ROLE"
                )
            )
            connection.commit()

        finally:
            connection.close()
            engine.dispose()


def _cleanup_registration(
    *,
    session_factory: SessionFactory,
    organization_id: UUID,
    user_id: UUID,
) -> None:
    session = session_factory()

    try:
        # Les modèles n'utilisent volontairement
        # aucune relationship() ORM.
        #
        # On impose donc explicitement l'ordre :
        # user_account -> organization.
        session.execute(
            delete(
                UserAccountModel
            ).where(
                UserAccountModel.id
                == user_id
            )
        )

        session.flush()

        session.execute(
            delete(
                OrganizationModel
            ).where(
                OrganizationModel.id
                == organization_id
            )
        )

        session.commit()

    except Exception:
        session.rollback()
        raise

    finally:
        session.close()


def test_registration_persists_organization_and_first_user(
    registration_database: tuple[
        Connection,
        SessionFactory,
    ],
) -> None:
    (
        _,
        session_factory,
    ) = registration_database

    suffix = uuid4().hex[:12]

    slug = (
        f"register-{suffix}"
    )

    email = (
        f"security-{suffix}"
        "@example.test"
    )

    password = (
        "integration-password"
    )

    password_hasher = (
        PasswordHasher()
    )

    service = (
        UserRegistrationService(
            unit_of_work=(
                SqlAlchemyUserRegistrationUnitOfWork(
                    session_factory
                )
            ),
            password_hasher=(
                password_hasher
            ),
        )
    )

    result = service.register(
        organization_name=(
            "Integration Security"
        ),
        organization_slug=slug,
        display_name=(
            "Security Responsible"
        ),
        email=email,
        password=password,
    )

    verification_session = (
        session_factory()
    )

    try:
        organization = (
            verification_session.scalar(
                select(
                    OrganizationModel
                ).where(
                    OrganizationModel.id
                    == result.organization.id
                )
            )
        )

        assert organization is not None

        assert (
            organization.name
            == "Integration Security"
        )

        assert (
            organization.slug
            == slug
        )

        assert (
            organization.is_active
            is True
        )

        user = (
            verification_session.scalar(
                select(
                    UserAccountModel
                ).where(
                    UserAccountModel.id
                    == result.user.id
                )
            )
        )

        assert user is not None

        assert (
            user.organization_id
            == result.organization.id
        )

        assert (
            user.email
            == email
        )

        assert (
            user.display_name
            == "Security Responsible"
        )

        assert (
            user.role
            == "security_responsible"
        )

        assert (
            user.is_active
            is True
        )

        assert (
            user.password_hash
            != password
        )

        assert (
            user.password_hash
            .startswith(
                "$argon2"
            )
        )

        assert (
            password_hasher
            .verify_password(
                password=password,
                password_hash=(
                    user.password_hash
                ),
            )
        )

    finally:
        verification_session.close()

        _cleanup_registration(
            session_factory=(
                session_factory
            ),
            organization_id=(
                result.organization.id
            ),
            user_id=(
                result.user.id
            ),
        )


def test_registration_transaction_rolls_back_if_user_insert_fails(
    registration_database: tuple[
        Connection,
        SessionFactory,
    ],
) -> None:
    (
        _,
        session_factory,
    ) = registration_database

    password_hasher = (
        PasswordHasher()
    )

    seed_organization_id = (
        uuid4()
    )

    conflicting_user_id = (
        uuid4()
    )

    suffix = uuid4().hex[:12]

    seed_session = (
        session_factory()
    )

    try:
        seed_organization = (
            OrganizationModel(
                id=(
                    seed_organization_id
                ),
                name=(
                    "Seed Organization"
                ),
                slug=(
                    f"seed-{suffix}"
                ),
                is_active=True,
                created_at=(
                    datetime.now(
                        UTC
                    )
                ),
            )
        )

        seed_user = (
            UserAccountModel(
                id=(
                    conflicting_user_id
                ),
                organization_id=(
                    seed_organization_id
                ),
                email=(
                    f"seed-{suffix}"
                    "@example.test"
                ),
                display_name=(
                    "Seed User"
                ),
                password_hash=(
                    password_hasher
                    .hash_password(
                        "seed-password"
                    )
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

        seed_session.add(
            seed_organization
        )

        # Le flush garantit explicitement
        # l'existence du parent avant l'enfant.
        seed_session.flush()

        seed_session.add(
            seed_user
        )

        seed_session.commit()

    finally:
        seed_session.close()

    new_organization_id = (
        uuid4()
    )

    new_slug = (
        f"rollback-{suffix}"
    )

    organization = Organization(
        id=new_organization_id,
        name=(
            "Rollback Organization"
        ),
        slug=new_slug,
        is_active=True,
        created_at=(
            datetime.now(
                UTC
            )
        ),
    )

    user = UserAccount(
        id=conflicting_user_id,
        organization_id=(
            new_organization_id
        ),
        email=(
            f"rollback-{suffix}"
            "@example.test"
        ),
        display_name=(
            "Rollback User"
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

    unit_of_work = (
        SqlAlchemyUserRegistrationUnitOfWork(
            session_factory
        )
    )

    with unit_of_work as active_uow:
        active_uow.registration.add_organization(
            organization
        )

        active_uow.registration.add_user(
            user=user,
            password_hash=(
                password_hasher
                .hash_password(
                    "rollback-password"
                )
            ),
        )

        with pytest.raises(
            UserRegistrationConflictError
        ):
            active_uow.commit()

    verification_session = (
        session_factory()
    )

    try:
        rolled_back_organization = (
            verification_session.scalar(
                select(
                    OrganizationModel
                ).where(
                    OrganizationModel.id
                    == new_organization_id
                )
            )
        )

        assert (
            rolled_back_organization
            is None
        )

        existing_user = (
            verification_session.get(
                UserAccountModel,
                conflicting_user_id,
            )
        )

        assert existing_user is not None

        assert (
            existing_user.organization_id
            == seed_organization_id
        )

    finally:
        verification_session.close()

        _cleanup_registration(
            session_factory=(
                session_factory
            ),
            organization_id=(
                seed_organization_id
            ),
            user_id=(
                conflicting_user_id
            ),
        )