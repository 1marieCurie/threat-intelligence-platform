from __future__ import annotations

from datetime import (
    UTC,
    datetime,
)
from uuid import UUID


def normalize_uuid(
    value: UUID,
    *,
    field_name: str,
) -> UUID:
    if not isinstance(value, UUID):
        raise TypeError(
            f"{field_name} must be a UUID"
        )

    if value.int == 0:
        raise ValueError(
            f"{field_name} must not be the nil UUID"
        )

    return value


def normalize_positive_integer(
    value: int,
    *,
    field_name: str,
) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
    ):
        raise TypeError(
            f"{field_name} must be an integer"
        )

    if value <= 0:
        raise ValueError(
            f"{field_name} must be positive"
        )

    return value


def normalize_required_text(
    value: str,
    *,
    field_name: str,
    max_length: int,
) -> str:
    if not isinstance(value, str):
        raise TypeError(
            f"{field_name} must be a string"
        )

    normalized_value = value.strip()

    if not normalized_value:
        raise ValueError(
            f"{field_name} must not be empty"
        )

    if len(normalized_value) > max_length:
        raise ValueError(
            f"{field_name} must not exceed "
            f"{max_length} characters"
        )

    if any(
        ord(character) < 32
        or ord(character) == 127
        for character in normalized_value
    ):
        raise ValueError(
            f"{field_name} must not contain "
            "control characters"
        )

    return normalized_value


def normalize_optional_text(
    value: str | None,
    *,
    field_name: str,
    max_length: int,
    lowercase: bool = False,
) -> str | None:
    if value is None:
        return None

    normalized_value = normalize_required_text(
        value,
        field_name=field_name,
        max_length=max_length,
    )

    if lowercase:
        return normalized_value.lower()

    return normalized_value


def normalize_datetime(
    value: datetime,
    *,
    field_name: str,
) -> datetime:
    if not isinstance(value, datetime):
        raise TypeError(
            f"{field_name} must be a datetime"
        )

    if (
        value.tzinfo is None
        or value.utcoffset() is None
    ):
        raise ValueError(
            f"{field_name} must be timezone-aware"
        )

    return value.astimezone(
        UTC
    )


def normalize_optional_datetime(
    value: datetime | None,
    *,
    field_name: str,
) -> datetime | None:
    if value is None:
        return None

    return normalize_datetime(
        value,
        field_name=field_name,
    )


def normalize_optional_boolean(
    value: bool | None,
    *,
    field_name: str,
) -> bool | None:
    if value is None:
        return None

    if not isinstance(value, bool):
        raise TypeError(
            f"{field_name} must be "
            "a boolean or None"
        )

    return value