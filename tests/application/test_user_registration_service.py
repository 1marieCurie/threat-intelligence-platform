from __future__ import annotations

from datetime import (
    UTC,
    datetime,
)
from types import TracebackType
from uuid import UUID

import pytest

from application.ports.outbound.user_registration_repository import (
    UserRegistrationRepositoryError,
)
from application.security.password_hasher import (
    PasswordHasher,
)
from application.services.user_registration_service import (
    OrganizationSlugAlreadyExistsError,
    UserRegistrationService,
)
from domain.organization import Organization
from domain.user_account import UserAccount


NOW = datetime(
    2026,
    8,
    23,
    14,
    30,
    tzinfo=UTC,
)

ORGANIZATION_ID = UUID(
    "11111111-1111-4111-8111-111111111111"
)

USER_ID = UUID(
    "22222222-2222-4222-8222-222222222222"
)


class FakeRegistrationRepository:
    def __init__(
        self,
        *,
        existing_slugs: set[str] | None = None,
        fail_user_creation: bool = False,
    ) -> None:
        self.existing_slugs = (
            set()
            if existing_slugs is None
            else set(existing_slugs)
        )
        self.fail_user_creation = (
            fail_user_creation
        )

        self.organization: (
            Organization | None
        ) = None

        self.user: (
            UserAccount | None
        ) = None

        self.password_hash: (
            str | None
        ) = None

    def organization_slug_exists(
        self,
        *,
        slug: str,
    ) -> bool:
        return slug in self.existing_slugs

    def add_organization(
        self,
        organization: Organization,
    ) -> None:
        self.organization = organization

    def add_user(
        self,
        *,
        user: UserAccount,
        password_hash: str,
    ) -> None:
        if self.fail_user_creation:
            raise UserRegistrationRepositoryError(
                "forced user creation failure"
            )

        self.user = user
        self.password_hash = (
            password_hash
        )


class FakeRegistrationUnitOfWork:
    def __init__(
        self,
        repository: (
            FakeRegistrationRepository
        ),
    ) -> None:
        self._repository = repository
        self.committed = False
        self.rolled_back = False
        self.entered = False

    @property
    def registration(
        self,
    ) -> FakeRegistrationRepository:
        if not self.entered:
            raise RuntimeError(
                "Unit of Work is not active"
            )

        return self._repository

    def __enter__(
        self,
    ) -> FakeRegistrationUnitOfWork:
        self.entered = True
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
            self.rolled_back = True

        self.entered = False

    def commit(
        self,
    ) -> None:
        self.committed = True

    def rollback(
        self,
    ) -> None:
        self.rolled_back = True


def _id_factory():
    values = iter(
        (
            ORGANIZATION_ID,
            USER_ID,
        )
    )

    return lambda: next(values)


def _service(
    repository: FakeRegistrationRepository,
) -> tuple[
    UserRegistrationService,
    FakeRegistrationUnitOfWork,
    PasswordHasher,
]:
    unit_of_work = (
        FakeRegistrationUnitOfWork(
            repository
        )
    )

    password_hasher = (
        PasswordHasher()
    )

    service = UserRegistrationService(
        unit_of_work=unit_of_work,
        password_hasher=password_hasher,
        clock=lambda: NOW,
        id_factory=_id_factory(),
    )

    return (
        service,
        unit_of_work,
        password_hasher,
    )


def test_register_creates_active_organization_and_security_responsible(
) -> None:
    repository = (
        FakeRegistrationRepository()
    )

    (
        service,
        unit_of_work,
        password_hasher,
    ) = _service(
        repository
    )

    result = service.register(
        organization_name=(
            "  Acme   Security  "
        ),
        organization_slug=(
            "  ACME-SECURITY  "
        ),
        display_name=(
            "  Marie   Curie  "
        ),
        email=(
            "  SECURITY@EXAMPLE.TEST  "
        ),
        password="secret-password",
    )

    assert unit_of_work.committed
    assert not unit_of_work.rolled_back

    assert (
        result.organization.id
        == ORGANIZATION_ID
    )
    assert (
        result.organization.name
        == "Acme Security"
    )
    assert (
        result.organization.slug
        == "acme-security"
    )
    assert result.organization.is_active

    assert (
        result.user.id
        == USER_ID
    )
    assert (
        result.user.organization_id
        == ORGANIZATION_ID
    )
    assert (
        result.user.email
        == "security@example.test"
    )
    assert (
        result.user.display_name
        == "Marie Curie"
    )
    assert (
        result.user.role
        == "security_responsible"
    )
    assert result.user.is_active

    assert (
        repository.password_hash
        is not None
    )
    assert (
        repository.password_hash
        != "secret-password"
    )
    assert (
        repository.password_hash
        .startswith("$argon2")
    )
    assert password_hasher.verify_password(
        password="secret-password",
        password_hash=(
            repository.password_hash
        ),
    )


def test_register_rejects_existing_slug(
) -> None:
    repository = (
        FakeRegistrationRepository(
            existing_slugs={
                "acme-security"
            }
        )
    )

    (
        service,
        unit_of_work,
        _,
    ) = _service(
        repository
    )

    with pytest.raises(
        OrganizationSlugAlreadyExistsError
    ):
        service.register(
            organization_name=(
                "Acme Security"
            ),
            organization_slug=(
                "ACME-SECURITY"
            ),
            display_name=(
                "Marie Curie"
            ),
            email=(
                "security@example.test"
            ),
            password=(
                "secret-password"
            ),
        )

    assert not unit_of_work.committed
    assert unit_of_work.rolled_back
    assert repository.user is None


def test_register_rolls_back_when_user_creation_fails(
) -> None:
    repository = (
        FakeRegistrationRepository(
            fail_user_creation=True
        )
    )

    (
        service,
        unit_of_work,
        _,
    ) = _service(
        repository
    )

    with pytest.raises(
        UserRegistrationRepositoryError
    ):
        service.register(
            organization_name=(
                "Acme Security"
            ),
            organization_slug=(
                "acme-security"
            ),
            display_name=(
                "Marie Curie"
            ),
            email=(
                "security@example.test"
            ),
            password=(
                "secret-password"
            ),
        )

    assert not unit_of_work.committed
    assert unit_of_work.rolled_back

    assert (
        repository.organization
        is not None
    )
    assert repository.user is None