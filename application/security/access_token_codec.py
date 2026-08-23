from __future__ import annotations

from dataclasses import dataclass
from datetime import (
    UTC,
    datetime,
    timedelta,
)
from uuid import UUID

import jwt


VALID_USER_ROLES = {
    "staff",
    "security_responsible",
}


@dataclass(
    frozen=True,
    slots=True,
)
class AccessTokenPrincipal:
    user_id: UUID
    organization_id: UUID
    session_id: UUID
    role: str


class AccessTokenCodec:
    def __init__(
        self,
        *,
        secret: str,
        issuer: str,
        audience: str,
        ttl_seconds: int,
    ) -> None:
        if not isinstance(
            secret,
            str,
        ):
            raise TypeError(
                "secret must be a string"
            )

        if len(secret) < 32:
            raise ValueError(
                "secret must contain at least "
                "32 characters"
            )

        if not isinstance(
            issuer,
            str,
        ) or not issuer.strip():
            raise ValueError(
                "issuer must not be empty"
            )

        if not isinstance(
            audience,
            str,
        ) or not audience.strip():
            raise ValueError(
                "audience must not be empty"
            )

        if (
            not isinstance(
                ttl_seconds,
                int,
            )
            or ttl_seconds <= 0
        ):
            raise ValueError(
                "ttl_seconds must be positive"
            )

        self._secret = secret
        self._issuer = issuer.strip()
        self._audience = (
            audience.strip()
        )
        self._ttl_seconds = (
            ttl_seconds
        )

    def issue_access_token(
        self,
        *,
        user_id: UUID,
        organization_id: UUID,
        session_id: UUID,
        role: str,
        issued_at: (
            datetime | None
        ) = None,
    ) -> str:
        if not isinstance(
            user_id,
            UUID,
        ):
            raise TypeError(
                "user_id must be UUID"
            )

        if not isinstance(
            organization_id,
            UUID,
        ):
            raise TypeError(
                "organization_id must be UUID"
            )

        if not isinstance(
            session_id,
            UUID,
        ):
            raise TypeError(
                "session_id must be UUID"
            )

        if role not in VALID_USER_ROLES:
            raise ValueError(
                "invalid user role"
            )

        now = (
            issued_at
            or datetime.now(
                UTC
            )
        )

        if (
            now.tzinfo is None
            or now.utcoffset()
            is None
        ):
            raise ValueError(
                "issued_at must be "
                "timezone-aware"
            )

        expires_at = (
            now
            + timedelta(
                seconds=(
                    self._ttl_seconds
                )
            )
        )

        payload = {
            "sub": str(user_id),
            "org": str(
                organization_id
            ),
            "sid": str(
                session_id
            ),
            "role": role,
            "token_type": "access",
            "iat": now,
            "exp": expires_at,
            "iss": self._issuer,
            "aud": self._audience,
        }

        return jwt.encode(
            payload,
            self._secret,
            algorithm="HS256",
        )

    def decode_access_token(
        self,
        token: str,
    ) -> (
        AccessTokenPrincipal
        | None
    ):
        if not isinstance(
            token,
            str,
        ):
            return None

        token = token.strip()

        if not token:
            return None

        try:
            payload = jwt.decode(
                token,
                self._secret,
                algorithms=[
                    "HS256",
                ],
                issuer=(
                    self._issuer
                ),
                audience=(
                    self._audience
                ),
                options={
                    "require": [
                        "sub",
                        "org",
                        "sid",
                        "role",
                        "token_type",
                        "iat",
                        "exp",
                        "iss",
                        "aud",
                    ],
                },
            )

        except jwt.PyJWTError:
            return None

        if (
            payload.get(
                "token_type"
            )
            != "access"
        ):
            return None

        role = payload.get(
            "role"
        )

        if (
            not isinstance(
                role,
                str,
            )
            or role
            not in VALID_USER_ROLES
        ):
            return None

        try:
            user_id = UUID(
                str(
                    payload["sub"]
                )
            )

            organization_id = UUID(
                str(
                    payload["org"]
                )
            )

            session_id = UUID(
                str(
                    payload["sid"]
                )
            )

        except (
            KeyError,
            TypeError,
            ValueError,
        ):
            return None

        return AccessTokenPrincipal(
            user_id=user_id,
            organization_id=(
                organization_id
            ),
            session_id=session_id,
            role=role,
        )