from __future__ import annotations

import re
from collections.abc import Iterable


MAX_CWE_ID_LENGTH = 32

_CWE_ID_PATTERN = re.compile(
    r"^(?:CWE-)?(\d+)$",
    re.IGNORECASE,
)


def normalize_cwe_id(
    value: object,
) -> str | None:
    """
    Normalise une référence CWE fournisseur vers CWE-<nombre>.

    Les valeurs invalides sont ignorées plutôt que transformées en
    entrées officielles. La présence dans le catalogue MITRE local
    devra ensuite être vérifiée par CWELookupService.
    """
    if not isinstance(
        value,
        str,
    ):
        return None

    normalized_value = value.strip()

    if (
        not normalized_value
        or len(normalized_value)
        > MAX_CWE_ID_LENGTH
    ):
        return None

    match = _CWE_ID_PATTERN.fullmatch(
        normalized_value
    )

    if match is None:
        return None

    numeric_id = int(
        match.group(1)
    )

    if numeric_id < 1:
        return None

    return f"CWE-{numeric_id}"


def normalize_cwe_ids(
    values: Iterable[object] | None,
) -> tuple[str, ...]:
    """
    Normalise et déduplique des références CWE.

    L'ordre de première apparition est conservé.
    """
    if values is None:
        return ()

    if isinstance(
        values,
        (str, bytes),
    ):
        raise TypeError(
            "cwe_ids must be an iterable "
            "of identifiers"
        )

    try:
        iterator = iter(
            values
        )
    except TypeError as error:
        raise TypeError(
            "cwe_ids must be iterable"
        ) from error

    normalized_values: list[str] = []
    seen: set[str] = set()

    for value in iterator:
        normalized_value = normalize_cwe_id(
            value
        )

        if normalized_value is None:
            continue

        if normalized_value in seen:
            continue

        seen.add(
            normalized_value
        )

        normalized_values.append(
            normalized_value
        )

    return tuple(
        normalized_values
    )