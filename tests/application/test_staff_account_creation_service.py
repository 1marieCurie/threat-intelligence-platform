from __future__ import annotations

from datetime import (
    UTC,
    datetime,
)
from types import TracebackType
from uuid import (
    UUID,
    uuid4,
)

import pytest

from application.security.password_hasher import (
    PasswordHasher,
)
from application.services.user_registration_service import (
    StaffEmailAlreadyExistsError,
    UserRegistrationService,
)
from domain.organization import Organization
from domain.user_account import UserAccount


NOW = datetime(
    2026,
    8,
    23,
    15,
    0,
    tzinfo=UTC,
)


class FakeRegistrationRepository:
    def __init__(
        self,
    ) -> None:
        self.email_exists = False

        self.email_checks: list[
            tuple[
                UUID,
                str,
            ]
        ] = []

        self.added_users: list[
            tuple[
                UserAccount,
                str,
            ]
        ] = []

    def organization_slug_exists(
        self,
        *,
        slug: str,
    ) -> bool:
        del slug
        return False

    def user_email_exists(
        self,
        *,
        organization_id: UUID,
        email: str,
    ) -> bool:
        self.email_checks.append(
            (
                organization_id,
                email,
            )
        )

        return self.email_exists

    def add_organization(
        self,
        organization: Organization,
    ) -> None:
        del organization

    def add_user(
        self,
        *,
        user: UserAccount,
        password_hash: str,
    ) -> None:
        self.added_users.append(
            (
                user,
                password_hash,
            )
        )


class FakeRegistrationUnitOfWork:
    def __init__(
        self,
        repository: (
            FakeRegistrationRepository
        ),
    ) -> None:
        self.registration = repository

        self.commit_count = 0
        self.rollback_count = 0

    def __enter__(
        self,
    ) -> FakeRegistrationUnitOfWork:
        return self

    def __exit__(
        self,
        exc_type: (
            type[BaseException]
            | None
        ),
        exc_value: (
            BaseException
            | None
        ),
        traceback: (
            TracebackType
            | None
        ),
    ) -> None:
        del exc_value
        del traceback

        if exc_type is not None:
            self.rollback_count += 1

    def commit(
        self,
    ) -> None:
        self.commit_count += 1

    def rollback(
        self,
    ) -> None:
        self.rollback_count += 1


def test_create_staff_account_forces_role_and_organization(
) -> None:
    organization_id = uuid4()
    user_id = uuid4()

    repository = (
        FakeRegistrationRepository()
    )

    unit_of_work = (
        FakeRegistrationUnitOfWork(
            repository
        )
    )

    password_hasher = (
        PasswordHasher()
    )

    service = (
        UserRegistrationService(
            unit_of_work=(
                unit_of_work
            ),
            password_hasher=(
                password_hasher
            ),
            clock=lambda: NOW,
            id_factory=lambda: user_id,
        )
    )

    user = (
        service.create_staff_account(
            organization_id=(
                organization_id
            ),
            display_name=(
                "  Marie   Curie  "
            ),
            email=(
                "  STAFF@EXAMPLE.TEST  "
            ),
            password=(
                "staff-password"
            ),
        )
    )

    assert (
        user.id
        == user_id
    )

    assert (
        user.organization_id
        == organization_id
    )

    assert (
        user.role
        == "staff"
    )

    assert (
        user.is_active
        is True
    )

    assert (
        user.display_name
        == "Marie Curie"
    )

    assert (
        user.email
        == "staff@example.test"
    )

    assert repository.email_checks == [
        (
            organization_id,
            "staff@example.test",
        )
    ]

    assert (
        len(
            repository.added_users
        )
        == 1
    )

    persisted_user, password_hash = (
        repository.added_users[0]
    )

    assert persisted_user == user

    assert (
        password_hash
        != "staff-password"
    )

    assert (
        password_hash.startswith(
            "$argon2"
        )
    )

    assert (
        password_hasher.verify_password(
            password=(
                "staff-password"
            ),
            password_hash=(
                password_hash
            ),
        )
    )

    assert (
        unit_of_work.commit_count
        == 1
    )


def test_create_staff_account_rejects_existing_email(
) -> None:
    repository = (
        FakeRegistrationRepository()
    )

    repository.email_exists = True

    unit_of_work = (
        FakeRegistrationUnitOfWork(
            repository
        )
    )

    service = (
        UserRegistrationService(
            unit_of_work=(
                unit_of_work
            ),
            password_hasher=(
                PasswordHasher()
            ),
            clock=lambda: NOW,
        )
    )

    with pytest.raises(
        StaffEmailAlreadyExistsError
    ):
        service.create_staff_account(
            organization_id=(
                uuid4()
            ),
            display_name=(
                "Existing Staff"
            ),
            email=(
                "existing@example.test"
            ),
            password=(
                "staff-password"
            ),
        )

    assert (
        repository.added_users
        == []
    )

    assert (
        unit_of_work.commit_count
        == 0
    )