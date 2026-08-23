from __future__ import annotations

from typing import Protocol
from uuid import UUID

from domain.organization import Organization
from domain.user_account import UserAccount


class UserRegistrationRepositoryError(
    RuntimeError
):
    pass


class UserRegistrationConflictError(
    UserRegistrationRepositoryError
):
    pass


class UserRegistrationRepository(
    Protocol
):
    def organization_slug_exists(
        self,
        *,
        slug: str,
    ) -> bool:
        ...

    def user_email_exists(
        self,
        *,
        organization_id: UUID,
        email: str,
    ) -> bool:
        ...

    def add_organization(
        self,
        organization: Organization,
    ) -> None:
        ...

    def add_user(
        self,
        *,
        user: UserAccount,
        password_hash: str,
    ) -> None:
        ...