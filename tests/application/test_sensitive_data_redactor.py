from typing import Any

import pytest

from application.security.sensitive_data_redactor import (
    REDACTED_VALUE,
    redact_sensitive_data,
)


def test_redacts_bearer_authorization_header() -> None:
    result = redact_sensitive_data(
        "Authorization: Bearer ghp_super_secret_token"
    )

    assert result == (
        f"Authorization: {REDACTED_VALUE}"
    )
    assert "ghp_super_secret_token" not in result


def test_redacts_github_token_assignment() -> None:
    result = redact_sensitive_data(
        "GITHUB_TOKEN=ghp_super_secret_token"
    )

    assert result == (
        f"GITHUB_TOKEN={REDACTED_VALUE}"
    )


def test_redacts_password_assignment() -> None:
    result = redact_sensitive_data(
        "password: database-password"
    )

    assert result == (
        f"password: {REDACTED_VALUE}"
    )


def test_redacts_database_url_password() -> None:
    result = redact_sensitive_data(
        "Connection failed for "
        "postgresql://app_user:secret-password"
        "@localhost:5432/threat_intelligence"
    )

    assert "secret-password" not in result
    assert (
        "postgresql://app_user:"
        f"{REDACTED_VALUE}@localhost"
        in result
    )


def test_redacts_multiple_secrets() -> None:
    result = redact_sensitive_data(
        "GITHUB_TOKEN=token-value; "
        "password=db-password; "
        "Authorization: Bearer bearer-value"
    )

    assert "token-value" not in result
    assert "db-password" not in result
    assert "bearer-value" not in result

    assert result.count(REDACTED_VALUE) == 3


def test_preserves_message_without_secret() -> None:
    message = "GitHub API unavailable"

    assert (
        redact_sensitive_data(message)
        == message
    )


def test_truncates_sanitized_message() -> None:
    result = redact_sensitive_data(
        "A" * 100,
        max_length=20,
    )

    assert result == "A" * 20


@pytest.mark.parametrize(
    "value",
    [
        None,
        123,
        True,
    ],
)
def test_rejects_non_string_value(
    value: Any,
) -> None:
    with pytest.raises(
        TypeError,
        match="value must be a string",
    ):
        redact_sensitive_data(value)


@pytest.mark.parametrize(
    "max_length",
    [
        True,
        1.5,
        "500",
        None,
    ],
)
def test_rejects_non_integer_max_length(
    max_length: Any,
) -> None:
    with pytest.raises(
        TypeError,
        match="max_length must be an integer",
    ):
        redact_sensitive_data(
            "message",
            max_length=max_length,
        )


@pytest.mark.parametrize(
    "max_length",
    [
        0,
        -1,
    ],
)
def test_rejects_invalid_max_length(
    max_length: int,
) -> None:
    with pytest.raises(
        ValueError,
        match=(
            "max_length must be greater "
            "than or equal to 1"
        ),
    ):
        redact_sensitive_data(
            "message",
            max_length=max_length,
        )

