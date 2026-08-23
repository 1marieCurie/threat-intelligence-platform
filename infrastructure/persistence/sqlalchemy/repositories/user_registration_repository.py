from __future__ import annotations

from uuid import UUID

from sqlalchemy import (
    func,
    select,
)
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from application.ports.outbound.user_registration_repository import (
    UserRegistrationRepositoryError,
)
from domain.organization import Organization
from domain.user_account import UserAccount
from infrastructure.persistence.models.assets import (
    OrganizationModel,
    UserAccountModel,
)


class SqlAlchemyUserRegistrationRepository:
    def __init__(
        self,
        *,
        session: Session,
    ) -> None:
        if session is None:
            raise ValueError(
                "session must not be None"
            )

        self._session = session

    def organization_slug_exists(
        self,
        *,
        slug: str,
    ) -> bool:
        normalized_slug = (
            slug.strip().lower()
        )

        try:
            organization_id = (
                self._session.scalar(
                    select(
                        OrganizationModel.id
                    )
                    .where(
                        OrganizationModel.slug
                        == normalized_slug
                    )
                    .limit(1)
                )
            )

        except SQLAlchemyError as error:
            raise (
                UserRegistrationRepositoryError(
                    (
                        "Unable to read "
                        "organization slug"
                    )
                )
            ) from error

        return (
            organization_id is not None
        )

    def user_email_exists(
        self,
        *,
        organization_id: UUID,
        email: str,
    ) -> bool:
        normalized_email = (
            email.strip().lower()
        )

        try:
            user_id = (
                self._session.scalar(
                    select(
                        UserAccountModel.id
                    )
                    .where(
                        UserAccountModel
                        .organization_id
                        == organization_id,
                        func.lower(
                            UserAccountModel.email
                        )
                        == normalized_email,
                    )
                    .limit(1)
                )
            )

        except SQLAlchemyError as error:
            raise (
                UserRegistrationRepositoryError(
                    (
                        "Unable to read "
                        "user email"
                    )
                )
            ) from error

        return (
            user_id is not None
        )

    def add_organization(
        self,
        organization: Organization,
    ) -> None:
        try:
            self._session.add(
                OrganizationModel(
                    id=organization.id,
                    name=organization.name,
                    slug=organization.slug,
                    is_active=(
                        organization.is_active
                    ),
                    created_at=(
                        organization.created_at
                    ),
                )
            )

        except SQLAlchemyError as error:
            raise (
                UserRegistrationRepositoryError(
                    (
                        "Unable to add "
                        "organization"
                    )
                )
            ) from error

    def add_user(
        self,
        *,
        user: UserAccount,
        password_hash: str,
    ) -> None:
        try:
            self._session.add(
                UserAccountModel(
                    id=user.id,
                    organization_id=(
                        user.organization_id
                    ),
                    email=user.email,
                    display_name=(
                        user.display_name
                    ),
                    password_hash=(
                        password_hash
                    ),
                    role=user.role,
                    is_active=(
                        user.is_active
                    ),
                    created_at=(
                        user.created_at
                    ),
                )
            )

        except SQLAlchemyError as error:
            raise (
                UserRegistrationRepositoryError(
                    (
                        "Unable to add "
                        "user account"
                    )
                )
            ) from error