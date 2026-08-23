from __future__ import annotations

import secrets
from dataclasses import dataclass
from hashlib import sha256
from hmac import compare_digest


@dataclass(
    frozen=True,
    slots=True,
)
class RefreshToken:
    value: str
    sha256: str


class RefreshTokenManager:
    def issue(
        self,
    ) -> RefreshToken:
        raw_token = (
            secrets.token_urlsafe(
                48
            )
        )

        return RefreshToken(
            value=raw_token,
            sha256=(
                self.hash_token(
                    raw_token
                )
            ),
        )

    @staticmethod
    def hash_token(
        raw_token: str,
    ) -> str:
        if not isinstance(
            raw_token,
            str,
        ):
            raise TypeError(
                "raw_token must be a string"
            )

        if not raw_token:
            raise ValueError(
                "raw_token must not be empty"
            )

        return sha256(
            raw_token.encode(
                "utf-8"
            )
        ).hexdigest()

    @classmethod
    def verify(
        cls,
        *,
        raw_token: str,
        expected_hash: str,
    ) -> bool:
        if not isinstance(
            raw_token,
            str,
        ):
            return False

        if not isinstance(
            expected_hash,
            str,
        ):
            return False

        if (
            not raw_token
            or not expected_hash
        ):
            return False

        actual_hash = (
            cls.hash_token(
                raw_token
            )
        )

        return compare_digest(
            actual_hash,
            expected_hash,
        )