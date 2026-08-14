from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID


def validate_uuid(
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


def normalize_required_text(
    value: str,
    *,
    field_name: str,
    lowercase: bool = False,
) -> str:
    if not isinstance(value, str):
        raise TypeError(
            f"{field_name} must be a string"
        )

    normalized_value = " ".join(
        value.strip().split()
    )

    if not normalized_value:
        raise ValueError(
            f"{field_name} must not be empty"
        )

    if lowercase:
        normalized_value = (
            normalized_value.lower()
        )

    return normalized_value


def normalize_optional_text(
    value: str | None,
    *,
    field_name: str,
    lowercase: bool = False,
) -> str | None:
    if value is None:
        return None

    return normalize_required_text(
        value,
        field_name=field_name,
        lowercase=lowercase,
    )


def normalize_choice(
    value: str,
    *,
    field_name: str,
    allowed_values: frozenset[str],
    uppercase: bool = False,
) -> str:
    normalized_value = normalize_required_text(
        value,
        field_name=field_name,
    )

    normalized_value = (
        normalized_value.upper()
        if uppercase
        else normalized_value.lower()
    )

    if normalized_value not in allowed_values:
        allowed = ", ".join(
            sorted(allowed_values)
        )
        raise ValueError(
            f"{field_name} must be one of: {allowed}"
        )

    return normalized_value


def normalize_datetime_utc(
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
        timezone.utc
    )


def validate_bool(
    value: bool,
    *,
    field_name: str,
) -> bool:
    if not isinstance(value, bool):
        raise TypeError(
            f"{field_name} must be a boolean"
        )

    return value


def validate_non_negative_int(
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

    if value < 0:
        raise ValueError(
            f"{field_name} must be greater than or equal to zero"
        )

    return value