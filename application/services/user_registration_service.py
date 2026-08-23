from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import (
    UTC,
    datetime,
)
from uuid import (
    UUID,
    uuid4,
)

from application.ports.outbound.user_registration_repository import (
    UserRegistrationConflictError,
)
from application.ports.outbound.user_registration_unit_of_work import (
    UserRegistrationUnitOfWork,
)
from application.security.password_hasher import (
    PasswordHasher,
)
from domain.organization import Organization
from domain.user_account import UserAccount


_SLUG_PATTERN = re.compile(
    r"^[a-z0-9]+(?:-[a-z0-9]+)*$"
)


class UserRegistrationError(
    RuntimeError
):
    pass


class InvalidRegistrationDataError(
    UserRegistrationError
):
    pass


class OrganizationSlugAlreadyExistsError(
    UserRegistrationError
):
    pass


@dataclass(
    frozen=True,
    slots=True,
)
class UserRegistrationResult:
    organization: Organization
    user: UserAccount


def _utc_now() -> datetime:
    return datetime.now(
        UTC
    )


class UserRegistrationService:
    def __init__(
        self,
        *,
        unit_of_work: (
            UserRegistrationUnitOfWork
        ),
        password_hasher: PasswordHasher,
        clock: Callable[
            [],
            datetime,
        ] = _utc_now,
        id_factory: Callable[
            [],
            UUID,
        ] = uuid4,
    ) -> None:
        if unit_of_work is None:
            raise ValueError(
                "unit_of_work must not be None"
            )

        if password_hasher is None:
            raise ValueError(
                "password_hasher must not be None"
            )

        if clock is None:
            raise ValueError(
                "clock must not be None"
            )

        if id_factory is None:
            raise ValueError(
                "id_factory must not be None"
            )

        self._unit_of_work = (
            unit_of_work
        )
        self._password_hasher = (
            password_hasher
        )
        self._clock = clock
        self._id_factory = (
            id_factory
        )

    def register(
        self,
        *,
        organization_name: str,
        organization_slug: str,
        display_name: str,
        email: str,
        password: str,
    ) -> UserRegistrationResult:
        normalized_organization_name = (
            self._normalize_name(
                organization_name,
                field_name=(
                    "organization_name"
                ),
            )
        )

        normalized_slug = (
            self._normalize_slug(
                organization_slug
            )
        )

        normalized_display_name = (
            self._normalize_name(
                display_name,
                field_name="display_name",
            )
        )

        normalized_email = (
            self._normalize_email(
                email
            )
        )

        normalized_password = (
            self._validate_password(
                password
            )
        )

        now = self._now()

        organization = Organization(
            id=self._new_id(),
            name=(
                normalized_organization_name
            ),
            slug=normalized_slug,
            is_active=True,
            created_at=now,
        )

        user = UserAccount(
            id=self._new_id(),
            organization_id=(
                organization.id
            ),
            email=normalized_email,
            display_name=(
                normalized_display_name
            ),
            role=(
                "security_responsible"
            ),
            is_active=True,
            created_at=now,
        )

        password_hash = (
            self._password_hasher
            .hash_password(
                normalized_password
            )
        )

        try:
            with (
                self._unit_of_work
                as unit_of_work
            ):
                repository = (
                    unit_of_work.registration
                )

                if (
                    repository
                    .organization_slug_exists(
                        slug=(
                            normalized_slug
                        )
                    )
                ):
                    raise (
                        OrganizationSlugAlreadyExistsError(
                            (
                                "Organization slug "
                                "already exists"
                            )
                        )
                    )

                repository.add_organization(
                    organization
                )

                repository.add_user(
                    user=user,
                    password_hash=(
                        password_hash
                    ),
                )

                unit_of_work.commit()

        except (
            UserRegistrationConflictError
        ) as error:
            raise (
                OrganizationSlugAlreadyExistsError(
                    (
                        "Organization slug "
                        "already exists"
                    )
                )
            ) from error

        return UserRegistrationResult(
            organization=organization,
            user=user,
        )

    @staticmethod
    def _normalize_name(
        value: str,
        *,
        field_name: str,
    ) -> str:
        if not isinstance(
            value,
            str,
        ):
            raise InvalidRegistrationDataError(
                f"{field_name} must be a string"
            )

        normalized = " ".join(
            value.strip().split()
        )

        if not normalized:
            raise InvalidRegistrationDataError(
                f"{field_name} must not be empty"
            )

        if len(normalized) > 255:
            raise InvalidRegistrationDataError(
                (
                    f"{field_name} must not "
                    "exceed 255 characters"
                )
            )

        return normalized

    @staticmethod
    def _normalize_slug(
        value: str,
    ) -> str:
        if not isinstance(
            value,
            str,
        ):
            raise InvalidRegistrationDataError(
                (
                    "organization_slug "
                    "must be a string"
                )
            )

        normalized = (
            value.strip().lower()
        )

        if (
            not normalized
            or len(normalized) > 63
            or _SLUG_PATTERN.fullmatch(
                normalized
            )
            is None
        ):
            raise InvalidRegistrationDataError(
                (
                    "organization_slug must "
                    "contain only lowercase "
                    "letters, digits and "
                    "single hyphens between "
                    "segments"
                )
            )

        return normalized

    @staticmethod
    def _normalize_email(
        value: str,
    ) -> str:
        if not isinstance(
            value,
            str,
        ):
            raise InvalidRegistrationDataError(
                "email must be a string"
            )

        normalized = (
            value.strip().lower()
        )

        if (
            not normalized
            or len(normalized) > 320
            or normalized.count("@") != 1
            or normalized.startswith("@")
            or normalized.endswith("@")
            or any(
                character.isspace()
                for character
                in normalized
            )
        ):
            raise InvalidRegistrationDataError(
                (
                    "email must be a valid "
                    "non-empty email address"
                )
            )

        return normalized

    @staticmethod
    def _validate_password(
        value: str,
    ) -> str:
        if not isinstance(
            value,
            str,
        ):
            raise InvalidRegistrationDataError(
                "password must be a string"
            )

        if not value:
            raise InvalidRegistrationDataError(
                "password must not be empty"
            )

        if len(value) > 1024:
            raise InvalidRegistrationDataError(
                (
                    "password must not exceed "
                    "1024 characters"
                )
            )

        return value

    def _now(
        self,
    ) -> datetime:
        now = self._clock()

        if not isinstance(
            now,
            datetime,
        ):
            raise TypeError(
                "clock must return datetime"
            )

        if (
            now.tzinfo is None
            or now.utcoffset()
            is None
        ):
            raise ValueError(
                (
                    "clock must return "
                    "timezone-aware datetime"
                )
            )

        return now.astimezone(
            UTC
        )

    def _new_id(
        self,
    ) -> UUID:
        value = self._id_factory()

        if not isinstance(
            value,
            UUID,
        ):
            raise TypeError(
                "id_factory must return UUID"
            )

        if value.int == 0:
            raise ValueError(
                (
                    "id_factory must not "
                    "return nil UUID"
                )
            )

        return value