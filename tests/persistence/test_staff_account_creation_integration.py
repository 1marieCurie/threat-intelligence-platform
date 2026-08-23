from __future__ import annotations

import os
from collections.abc import Iterator
from datetime import (
    UTC,
    datetime,
)
from pathlib import Path
from uuid import uuid4

import pytest
from dotenv import load_dotenv
from sqlalchemy import (
    create_engine,
    delete,
    select,
    text,
)
from sqlalchemy.orm import (
    Session,
    sessionmaker,
)
from sqlalchemy.pool import NullPool

from application.security.password_hasher import (
    PasswordHasher,
)
from application.services.user_registration_service import (
    UserRegistrationService,
)
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


@pytest.fixture
def session_factory(
) -> Iterator[
    sessionmaker[Session]
]:
    database_url = os.environ.get(
        "MIGRATION_DATABASE_URL"
    )

    if not database_url:
        raise RuntimeError(
            "MIGRATION_DATABASE_URL is not defined"
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

    factory = sessionmaker(
        bind=connection,
        class_=Session,
        autoflush=False,
        expire_on_commit=False,
    )

    try:
        yield factory

    finally:
        connection.execute(
            text(
                "RESET ROLE"
            )
        )
        connection.commit()

        connection.close()
        engine.dispose()


def test_creates_staff_account_in_existing_organization(
    session_factory: sessionmaker[
        Session
    ],
) -> None:
    organization_id = uuid4()
    suffix = uuid4().hex[:12]

    email = (
        f"staff-{suffix}"
        "@example.test"
    )

    password = (
        "staff-integration-password"
    )

    seed_session = (
        session_factory()
    )

    try:
        seed_session.add(
            OrganizationModel(
                id=organization_id,
                name="Staff Integration",
                slug=(
                    f"staff-integration-{suffix}"
                ),
                is_active=True,
                created_at=(
                    datetime.now(
                        UTC
                    )
                ),
            )
        )

        seed_session.commit()

    finally:
        seed_session.close()

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

    user = (
        service.create_staff_account(
            organization_id=(
                organization_id
            ),
            display_name=(
                "Integration Staff"
            ),
            email=email,
            password=password,
        )
    )

    verification_session = (
        session_factory()
    )

    try:
        stored_user = (
            verification_session.scalar(
                select(
                    UserAccountModel
                ).where(
                    UserAccountModel.id
                    == user.id
                )
            )
        )

        assert stored_user is not None

        assert (
            stored_user.organization_id
            == organization_id
        )

        assert (
            stored_user.email
            == email
        )

        assert (
            stored_user.display_name
            == "Integration Staff"
        )

        assert (
            stored_user.role
            == "staff"
        )

        assert (
            stored_user.is_active
            is True
        )

        assert (
            stored_user.password_hash
            != password
        )

        assert (
            stored_user.password_hash
            .startswith(
                "$argon2"
            )
        )

        assert (
            password_hasher
            .verify_password(
                password=password,
                password_hash=(
                    stored_user
                    .password_hash
                ),
            )
        )

    finally:
        verification_session.close()

        cleanup_session = (
            session_factory()
        )

        try:
            cleanup_session.execute(
                delete(
                    UserAccountModel
                ).where(
                    UserAccountModel.id
                    == user.id
                )
            )

            cleanup_session.flush()

            cleanup_session.execute(
                delete(
                    OrganizationModel
                ).where(
                    OrganizationModel.id
                    == organization_id
                )
            )

            cleanup_session.commit()

        finally:
            cleanup_session.close()