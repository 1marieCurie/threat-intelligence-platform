from __future__ import annotations

import re

from application.security.sensitive_data_redactor import (
    redact_sensitive_data,
)


_CVE_IDENTIFIER_PATTERN = re.compile(
    r"\bCVE-[A-Z0-9._-]+\b",
    flags=re.IGNORECASE,
)

_CVE_REDACTED_VALUE = "[CVE_REDACTED]"
_DEFAULT_MAX_LENGTH = 500


def sanitize_exception_message(
    error: BaseException,
    *,
    max_length: int = _DEFAULT_MAX_LENGTH,
) -> str:
    """
    Retourne un message d'erreur utilisable dans les logs
    et les métadonnées opérationnelles.

    Les éléments suivants sont masqués :

    - credentials dans les URL ;
    - secrets et valeurs d'autorisation ;
    - identifiants CVE ;
    - messages excessivement longs.

    Le type de l'exception n'est pas inclus. Il doit être stocké
    séparément dans un champ structuré.
    """
    if not isinstance(
        error,
        BaseException,
    ):
        raise TypeError(
            "error must be an exception"
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
            "max_length must be greater than zero"
        )

    raw_message = str(
        error
    ).strip()

    if not raw_message:
        raw_message = (
            "No error message was provided."
        )

    sanitized_message = (
        redact_sensitive_data(
            raw_message,
            max_length=max_length,
        )
    )

    return _CVE_IDENTIFIER_PATTERN.sub(
        _CVE_REDACTED_VALUE,
        sanitized_message,
    )


def build_sanitized_error_summary(
    error: BaseException,
    *,
    max_length: int = _DEFAULT_MAX_LENGTH,
) -> str:
    """
    Construit un résumé contenant le type et le message assaini.
    """
    return (
        f"{type(error).__name__}: "
        f"{sanitize_exception_message(
            error,
            max_length=max_length,
        )}"
    )