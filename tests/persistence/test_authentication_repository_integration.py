from __future__ import annotations

import os
from collections.abc import (
    Callable,
    Iterator,
)
from datetime import (
    UTC,
    datetime,
    timedelta,
)
from pathlib import Path
from uuid import (
    UUID,
    uuid4,
)

import pytest
from dotenv import load_dotenv
from sqlalchemy import (
    Engine,
    create_engine,
    delete,
    event,
)
from sqlalchemy.engine import (
    Connection,
)
from sqlalchemy.orm import (
    Session,
    SessionTransaction,
    sessionmaker,
)

from application.models.authentication import (
    AuthenticationSession,
)
from infrastructure.persistence.models.assets import (
    OrganizationModel,
    UserAccountModel,
)
from infrastructure.persistence.models.auth import (
    AuthSessionModel,
)
from infrastructure.persistence.sqlalchemy.repositories.authentication_repository import (
    SqlAlchemyAuthenticationRepository,
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


NOW = datetime(
    2026,
    8,
    21,
    16,
    0,
    tzinfo=UTC,
)


class _AuthenticationOwnerSession(
    Session
):
    pass


AuthenticationSessionFactory = Callable[
    [],
    Session,
]


@event.listens_for(
    _AuthenticationOwnerSession,
    "after_begin",
)
def _set_owner_role(
    session: Session,
    transaction: SessionTransaction,
    connection: Connection,
) -> None:
    del session
    del transaction

    connection.exec_driver_sql(
        "SET LOCAL ROLE "
        "threat_intel_owner"
    )


@pytest.fixture
def authentication_session_factory(
) -> Iterator[
    AuthenticationSessionFactory
]:
    database_url = os.environ.get(
        "MIGRATION_DATABASE_URL"
    )

    if not database_url:
        raise RuntimeError(
            "MIGRATION_DATABASE_URL "
            "is not defined"
        )

    engine: Engine = create_engine(
        database_url,
        pool_pre_ping=True,
        future=True,
    )

    factory = sessionmaker(
        bind=engine,
        class_=(
            _AuthenticationOwnerSession
        ),
        autoflush=False,
        expire_on_commit=False,
    )

    try:
        yield factory

    finally:
        engine.dispose()


@pytest.fixture
def authentication_users(
    authentication_session_factory: (
        AuthenticationSessionFactory
    ),
) -> Iterator[
    tuple[
        UUID,
        UUID,
        UUID,
    ]
]:
    first_organization_id = (
        uuid4()
    )

    second_organization_id = (
        uuid4()
    )

    first_user_id = uuid4()
    second_user_id = uuid4()

    shared_email = (
        "shared-auth@example.test"
    )

    with (
        authentication_session_factory()
        as session
    ):
        session.add_all(
            [
                OrganizationModel(
                    id=(
                        first_organization_id
                    ),
                    name=(
                        "Auth Test A "
                        f"{uuid4().hex}"
                    ),
                    is_active=True,
                    created_at=NOW,
                ),
                OrganizationModel(
                    id=(
                        second_organization_id
                    ),
                    name=(
                        "Auth Test B "
                        f"{uuid4().hex}"
                    ),
                    is_active=True,
                    created_at=NOW,
                ),
            ]
        )

        session.add_all(
            [
                UserAccountModel(
                    id=first_user_id,
                    organization_id=(
                        first_organization_id
                    ),
                    email=shared_email,
                    display_name=(
                        "Tenant A User"
                    ),
                    password_hash=(
                        "tenant-a-password-hash"
                    ),
                    role="staff",
                    is_active=True,
                    created_at=NOW,
                ),
                UserAccountModel(
                    id=second_user_id,
                    organization_id=(
                        second_organization_id
                    ),
                    email=shared_email,
                    display_name=(
                        "Tenant B User"
                    ),
                    password_hash=(
                        "tenant-b-password-hash"
                    ),
                    role=(
                        "security_responsible"
                    ),
                    is_active=True,
                    created_at=NOW,
                ),
            ]
        )

        session.commit()

    try:
        yield (
            first_organization_id,
            first_user_id,
            second_organization_id,
        )

    finally:
        with (
            authentication_session_factory()
            as session
        ):
            session.execute(
                delete(
                    AuthSessionModel
                ).where(
                    AuthSessionModel.organization_id.in_(
                        [
                            first_organization_id,
                            second_organization_id,
                        ]
                    )
                )
            )

            session.execute(
                delete(
                    UserAccountModel
                ).where(
                    UserAccountModel.organization_id.in_(
                        [
                            first_organization_id,
                            second_organization_id,
                        ]
                    )
                )
            )

            session.execute(
                delete(
                    OrganizationModel
                ).where(
                    OrganizationModel.id.in_(
                        [
                            first_organization_id,
                            second_organization_id,
                        ]
                    )
                )
            )

            session.commit()


def test_user_login_lookup_is_tenant_scoped(
    authentication_session_factory: (
        AuthenticationSessionFactory
    ),
    authentication_users: tuple[
        UUID,
        UUID,
        UUID,
    ],
) -> None:
    (
        first_organization_id,
        first_user_id,
        second_organization_id,
    ) = authentication_users

    with (
        authentication_session_factory()
        as session
    ):
        repository = (
            SqlAlchemyAuthenticationRepository(
                session=session
            )
        )

        first = (
            repository.find_user_for_login(
                organization_id=(
                    first_organization_id
                ),
                email=(
                    "SHARED-AUTH@EXAMPLE.TEST"
                ),
            )
        )

        second = (
            repository.find_user_for_login(
                organization_id=(
                    second_organization_id
                ),
                email=(
                    "shared-auth@example.test"
                ),
            )
        )

        missing = (
            repository.find_user_for_login(
                organization_id=uuid4(),
                email=(
                    "shared-auth@example.test"
                ),
            )
        )

    assert first is not None
    assert second is not None

    assert (
        first.user.id
        == first_user_id
    )

    assert (
        first.user.organization_id
        == first_organization_id
    )

    assert (
        first.password_hash
        == "tenant-a-password-hash"
    )

    assert (
        second.user.organization_id
        == second_organization_id
    )

    assert (
        second.password_hash
        == "tenant-b-password-hash"
    )

    assert missing is None


def test_authentication_session_lifecycle(
    authentication_session_factory: (
        AuthenticationSessionFactory
    ),
    authentication_users: tuple[
        UUID,
        UUID,
        UUID,
    ],
) -> None:
    (
        organization_id,
        user_id,
        _,
    ) = authentication_users

    session_id = uuid4()

    first_hash = "a" * 64
    second_hash = "b" * 64

    authentication_session = (
        AuthenticationSession(
            id=session_id,
            organization_id=(
                organization_id
            ),
            user_id=user_id,
            refresh_token_hash=(
                first_hash
            ),
            created_at=NOW,
            expires_at=(
                NOW
                + timedelta(
                    days=30
                )
            ),
        )
    )

    with (
        authentication_session_factory()
        as database_session
    ):
        repository = (
            SqlAlchemyAuthenticationRepository(
                session=database_session
            )
        )

        repository.add_session(
            authentication_session
        )

        database_session.commit()

        stored = (
            repository.find_session_by_id(
                organization_id=(
                    organization_id
                ),
                user_id=user_id,
                session_id=session_id,
            )
        )

        assert stored is not None

        assert (
            stored.refresh_token_hash
            == first_hash
        )

        rotated = (
            repository.rotate_refresh_token(
                session_id=session_id,
                current_refresh_token_hash=(
                    first_hash
                ),
                new_refresh_token_hash=(
                    second_hash
                ),
                new_expires_at=(
                    NOW
                    + timedelta(
                        days=30
                    )
                ),
            )
        )

        assert rotated is True

        database_session.commit()

        assert (
            repository
            .find_session_by_refresh_token_hash(
                refresh_token_hash=(
                    first_hash
                )
            )
            is None
        )

        refreshed = (
            repository
            .find_session_by_refresh_token_hash(
                refresh_token_hash=(
                    second_hash
                )
            )
        )

        assert refreshed is not None
        assert (
            refreshed.id
            == session_id
        )

        revoked_at = (
            NOW
            + timedelta(
                minutes=10
            )
        )

        revoked = (
            repository.revoke_session(
                session_id=session_id,
                revoked_at=revoked_at,
            )
        )

        assert revoked is True

        database_session.commit()

        final_session = (
            repository.find_session_by_id(
                organization_id=(
                    organization_id
                ),
                user_id=user_id,
                session_id=session_id,
            )
        )

        assert final_session is not None

        assert (
            final_session.revoked_at
            == revoked_at
        )