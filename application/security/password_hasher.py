from __future__ import annotations

from argon2 import PasswordHasher as Argon2PasswordHasher
from argon2.exceptions import (
    InvalidHashError,
    VerificationError,
    VerifyMismatchError,
)


DISABLED_PASSWORD_HASH = (
    "!authentication-not-configured!"
)


class PasswordHasher:
    def __init__(self) -> None:
        self._hasher = (
            Argon2PasswordHasher()
        )

    def hash_password(
        self,
        password: str,
    ) -> str:
        if not isinstance(
            password,
            str,
        ):
            raise TypeError(
                "password must be a string"
            )

        if not password:
            raise ValueError(
                "password must not be empty"
            )

        return self._hasher.hash(
            password
        )

    def verify_password(
        self,
        *,
        password: str,
        password_hash: str,
    ) -> bool:
        if not isinstance(
            password,
            str,
        ):
            raise TypeError(
                "password must be a string"
            )

        if not isinstance(
            password_hash,
            str,
        ):
            raise TypeError(
                "password_hash must be a string"
            )

        if (
            not password
            or not password_hash
            or password_hash
            == DISABLED_PASSWORD_HASH
        ):
            return False

        try:
            return self._hasher.verify(
                password_hash,
                password,
            )

        except (
            VerifyMismatchError,
            VerificationError,
            InvalidHashError,
        ):
            return False

    def needs_rehash(
        self,
        password_hash: str,
    ) -> bool:
        if not isinstance(
            password_hash,
            str,
        ):
            raise TypeError(
                "password_hash must be a string"
            )

        if (
            not password_hash
            or password_hash
            == DISABLED_PASSWORD_HASH
        ):
            return False

        try:
            return (
                self._hasher
                .check_needs_rehash(
                    password_hash
                )
            )

        except InvalidHashError:
            return False