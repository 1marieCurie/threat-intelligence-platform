from __future__ import annotations

import re


REDACTED_VALUE = "[REDACTED]"
DEFAULT_MAX_LENGTH = 500


_AUTHORIZATION_PATTERN = re.compile(
    r"(?i)\b(authorization\s*:\s*)"
    r"(?:bearer|token|basic)\s+\S+"
)


_SECRET_ASSIGNMENT_PATTERN = re.compile(
    r"(?i)\b("
    r"github_token"
    r"|access_token"
    r"|refresh_token"
    r"|session_token"
    r"|id_token"
    r"|api_token"
    r"|token"
    r"|api_key"
    r"|auth_key"
    r"|client_secret"
    r"|password"
    r"|passwd"
    r"|secret"
    r")"
    r"(\s*[=:]\s*)"
    r"([^\s,;&#]+)"
)


_URI_CREDENTIALS_PATTERN = re.compile(
    r"(?P<scheme>"
    r"[a-zA-Z][a-zA-Z0-9+.-]*://"
    r")"
    r"(?P<username>[^:/@\s]+)"
    r":"
    r"(?P<password>[^@\s]+)"
    r"@"
)


def redact_sensitive_data(
    value: str,
    *,
    max_length: int = DEFAULT_MAX_LENGTH,
) -> str:
    """
    Masque les secrets courants présents dans les messages.

    Les formats pris en charge comprennent :

    - Authorization: Bearer <secret>
    - token=<secret>
    - api_key:<secret>
    - credentials dans les URL
    """

    if not isinstance(value, str):
        raise TypeError(
            "value must be a string"
        )

    if (
        isinstance(max_length, bool)
        or not isinstance(max_length, int)
    ):
        raise TypeError(
            "max_length must be an integer"
        )

    if max_length < 1:
        raise ValueError(
            "max_length must be greater "
            "than or equal to 1"
        )

    sanitized = (
        _URI_CREDENTIALS_PATTERN.sub(
            _redact_uri_credentials,
            value,
        )
    )

    sanitized = (
        _AUTHORIZATION_PATTERN.sub(
            rf"\1{REDACTED_VALUE}",
            sanitized,
        )
    )

    sanitized = (
        _SECRET_ASSIGNMENT_PATTERN.sub(
            rf"\1\2{REDACTED_VALUE}",
            sanitized,
        )
    )

    return sanitized[:max_length]


def _redact_uri_credentials(
    match: re.Match[str],
) -> str:
    scheme = match.group(
        "scheme"
    )

    username = match.group(
        "username"
    )

    return (
        f"{scheme}"
        f"{username}:"
        f"{REDACTED_VALUE}@"
    )