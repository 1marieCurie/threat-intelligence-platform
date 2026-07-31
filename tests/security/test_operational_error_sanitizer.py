from __future__ import annotations

import pytest

from application.security.operational_error_sanitizer import (
    build_sanitized_error_summary,
    sanitize_exception_message,
)


def test_sanitize_exception_message_redacts_secret_and_cve(
) -> None:
    secret = "super-secret-password"
    cve_id = "CVE-2021-44228"

    error = RuntimeError(
        "DATABASE_URL="
        "postgresql://user:"
        f"{secret}@localhost/database "
        f"while processing {cve_id}"
    )

    result = sanitize_exception_message(
        error
    )

    assert secret not in result
    assert cve_id not in result

    assert "[REDACTED]" in result
    assert "[CVE_REDACTED]" in result


def test_sanitize_exception_message_handles_empty_message(
) -> None:
    result = sanitize_exception_message(
        RuntimeError()
    )

    assert result == (
        "No error message was provided."
    )


def test_build_summary_includes_error_type(
) -> None:
    result = build_sanitized_error_summary(
        TimeoutError(
            "provider unavailable"
        )
    )

    assert result == (
        "TimeoutError: provider unavailable"
    )


@pytest.mark.parametrize(
    "invalid_length",
    [
        True,
        1.5,
        "500",
        None,
    ],
)
def test_sanitizer_rejects_invalid_length_type(
    invalid_length: object,
) -> None:
    with pytest.raises(
        TypeError,
        match="max_length must be an integer",
    ):
        sanitize_exception_message(
            RuntimeError("failure"),
            max_length=invalid_length,  # type: ignore[arg-type]
        )


@pytest.mark.parametrize(
    "invalid_length",
    [
        0,
        -1,
    ],
)
def test_sanitizer_rejects_non_positive_length(
    invalid_length: int,
) -> None:
    with pytest.raises(
        ValueError,
        match=(
            "max_length must be "
            "greater than zero"
        ),
    ):
        sanitize_exception_message(
            RuntimeError("failure"),
            max_length=invalid_length,
        )