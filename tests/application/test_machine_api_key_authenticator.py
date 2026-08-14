from __future__ import annotations

from uuid import uuid4

from application.security.machine_api_key_authenticator import (
    MachineApiCredential,
    MachineApiKeyAuthenticator,
)


def test_machine_api_key_resolves_tenant_and_machine(
) -> None:
    api_key = "test-machine-secret"

    organization_id = uuid4()
    machine_uid = uuid4()

    key_hash = (
        MachineApiKeyAuthenticator
        .hash_api_key(api_key)
    )

    authenticator = (
        MachineApiKeyAuthenticator(
            [
                MachineApiCredential(
                    key_sha256=key_hash,
                    organization_id=(
                        organization_id
                    ),
                    machine_uid=machine_uid,
                )
            ]
        )
    )

    principal = (
        authenticator.authenticate(
            api_key
        )
    )

    assert principal is not None

    assert (
        principal.organization_id
        == organization_id
    )

    assert (
        principal.machine_uid
        == machine_uid
    )


def test_unknown_machine_api_key_is_rejected(
) -> None:
    authenticator = (
        MachineApiKeyAuthenticator([])
    )

    assert (
        authenticator.authenticate(
            "unknown"
        )
        is None
    )


def test_inactive_machine_api_key_is_rejected(
) -> None:
    api_key = "inactive-key"

    authenticator = (
        MachineApiKeyAuthenticator(
            [
                MachineApiCredential(
                    key_sha256=(
                        MachineApiKeyAuthenticator
                        .hash_api_key(
                            api_key
                        )
                    ),
                    organization_id=uuid4(),
                    machine_uid=uuid4(),
                    is_active=False,
                )
            ]
        )
    )

    assert (
        authenticator.authenticate(
            api_key
        )
        is None
    )