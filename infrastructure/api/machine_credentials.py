from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any
from uuid import UUID

from dotenv import load_dotenv

from application.security.machine_api_key_authenticator import (
    MachineApiCredential,
    MachineApiKeyAuthenticator,
)


PROJECT_ROOT = (
    Path(__file__).resolve().parents[2]
)

ENV_FILE = PROJECT_ROOT / ".env"

load_dotenv(
    dotenv_path=ENV_FILE,
    override=False,
)


class MachineCredentialConfigurationError(
    RuntimeError
):
    pass


def load_machine_api_key_authenticator(
) -> MachineApiKeyAuthenticator:
    raw_configuration = os.environ.get(
        "TIP_MACHINE_CREDENTIALS_JSON"
    )

    if raw_configuration is None:
        raise MachineCredentialConfigurationError(
            "TIP_MACHINE_CREDENTIALS_JSON "
            "is not defined"
        )

    try:
        parsed = json.loads(
            raw_configuration
        )

    except json.JSONDecodeError as error:
        raise MachineCredentialConfigurationError(
            "TIP_MACHINE_CREDENTIALS_JSON "
            "must contain valid JSON"
        ) from error

    if not isinstance(parsed, list):
        raise MachineCredentialConfigurationError(
            "TIP_MACHINE_CREDENTIALS_JSON "
            "must be a JSON array"
        )

    credentials = [
        _parse_credential(item)
        for item in parsed
    ]

    return MachineApiKeyAuthenticator(
        credentials
    )


def _parse_credential(
    value: Any,
) -> MachineApiCredential:
    if not isinstance(value, dict):
        raise MachineCredentialConfigurationError(
            "Each machine credential "
            "must be a JSON object"
        )

    allowed_keys = {
        "key_sha256",
        "organization_id",
        "machine_uid",
        "is_active",
    }

    unknown_keys = (
        set(value)
        - allowed_keys
    )

    if unknown_keys:
        raise MachineCredentialConfigurationError(
            "Unknown machine credential "
            f"fields: {sorted(unknown_keys)!r}"
        )

    required_keys = {
        "key_sha256",
        "organization_id",
        "machine_uid",
    }

    missing_keys = (
        required_keys
        - set(value)
    )

    if missing_keys:
        raise MachineCredentialConfigurationError(
            "Missing machine credential "
            f"fields: {sorted(missing_keys)!r}"
        )

    try:
        organization_id = UUID(
            str(value["organization_id"])
        )

        machine_uid = UUID(
            str(value["machine_uid"])
        )

    except (
        TypeError,
        ValueError,
    ) as error:
        raise MachineCredentialConfigurationError(
            "Machine credential UUIDs "
            "are invalid"
        ) from error

    is_active = value.get(
        "is_active",
        True,
    )

    if not isinstance(
        is_active,
        bool,
    ):
        raise MachineCredentialConfigurationError(
            "Machine credential is_active "
            "must be boolean"
        )

    try:
        return MachineApiCredential(
            key_sha256=str(
                value["key_sha256"]
            ),
            organization_id=organization_id,
            machine_uid=machine_uid,
            is_active=is_active,
        )

    except (
        TypeError,
        ValueError,
    ) as error:
        raise MachineCredentialConfigurationError(
            "Invalid machine credential"
        ) from error