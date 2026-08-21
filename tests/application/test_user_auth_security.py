from __future__ import annotations

from datetime import (
    UTC,
    datetime,
    timedelta,
)
from uuid import uuid4

import pytest

from application.security.access_token_codec import (
    AccessTokenCodec,
)
from application.security.password_hasher import (
    DISABLED_PASSWORD_HASH,
    PasswordHasher,
)
from application.security.refresh_tokens import (
    RefreshTokenManager,
)


JWT_SECRET = (
    "development-test-secret-"
    "0123456789abcdef0123456789abcdef"
)


def _codec() -> AccessTokenCodec:
    return AccessTokenCodec(
        secret=JWT_SECRET,
        issuer=(
            "threat-intelligence-platform"
        ),
        audience=(
            "threat-intelligence-platform-web"
        ),
        ttl_seconds=900,
    )


def test_password_hash_and_verify(
) -> None:
    hasher = PasswordHasher()

    password = (
        "ExamplePassword2026!"
    )

    password_hash = (
        hasher.hash_password(
            password
        )
    )

    assert (
        password_hash
        != password
    )

    assert password_hash.startswith(
        "$argon2"
    )

    assert (
        hasher.verify_password(
            password=password,
            password_hash=password_hash,
        )
        is True
    )


def test_wrong_password_is_rejected(
) -> None:
    hasher = PasswordHasher()

    password_hash = (
        hasher.hash_password(
            "CorrectPassword2026!"
        )
    )

    assert (
        hasher.verify_password(
            password=(
                "WrongPassword2026!"
            ),
            password_hash=(
                password_hash
            ),
        )
        is False
    )


def test_disabled_password_is_rejected(
) -> None:
    hasher = PasswordHasher()

    assert (
        hasher.verify_password(
            password=(
                "AnyPassword2026!"
            ),
            password_hash=(
                DISABLED_PASSWORD_HASH
            ),
        )
        is False
    )


def test_refresh_tokens_are_random_and_hashed(
) -> None:
    manager = (
        RefreshTokenManager()
    )

    first = manager.issue()
    second = manager.issue()

    assert (
        first.value
        != second.value
    )

    assert (
        first.sha256
        != second.sha256
    )

    assert len(
        first.sha256
    ) == 64

    assert (
        manager.verify(
            raw_token=first.value,
            expected_hash=(
                first.sha256
            ),
        )
        is True
    )


def test_refresh_token_rejects_wrong_value(
) -> None:
    manager = (
        RefreshTokenManager()
    )

    token = manager.issue()

    assert (
        manager.verify(
            raw_token="wrong-token",
            expected_hash=(
                token.sha256
            ),
        )
        is False
    )


def test_access_token_round_trip(
) -> None:
    codec = _codec()

    user_id = uuid4()
    organization_id = uuid4()
    session_id = uuid4()

    token = (
        codec.issue_access_token(
            user_id=user_id,
            organization_id=(
                organization_id
            ),
            session_id=session_id,
            role="staff",
        )
    )

    principal = (
        codec.decode_access_token(
            token
        )
    )

    assert principal is not None

    assert (
        principal.user_id
        == user_id
    )

    assert (
        principal.organization_id
        == organization_id
    )

    assert (
        principal.session_id
        == session_id
    )

    assert (
        principal.role
        == "staff"
    )


def test_access_token_rejects_invalid_role(
) -> None:
    codec = _codec()

    with pytest.raises(
        ValueError,
        match="invalid user role",
    ):
        codec.issue_access_token(
            user_id=uuid4(),
            organization_id=uuid4(),
            session_id=uuid4(),
            role="admin",
        )


def test_access_token_rejects_expired_token(
) -> None:
    codec = _codec()

    issued_at = (
        datetime.now(
            UTC
        )
        - timedelta(
            hours=1
        )
    )

    token = (
        codec.issue_access_token(
            user_id=uuid4(),
            organization_id=uuid4(),
            session_id=uuid4(),
            role=(
                "security_responsible"
            ),
            issued_at=issued_at,
        )
    )

    assert (
        codec.decode_access_token(
            token
        )
        is None
    )


def test_access_token_rejects_tampering(
) -> None:
    codec = _codec()

    token = (
        codec.issue_access_token(
            user_id=uuid4(),
            organization_id=uuid4(),
            session_id=uuid4(),
            role="staff",
        )
    )

    tampered = (
        token[:-1]
        + (
            "a"
            if token[-1] != "a"
            else "b"
        )
    )

    assert (
        codec.decode_access_token(
            tampered
        )
        is None
    )