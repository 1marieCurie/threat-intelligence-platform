from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from uuid import UUID


@dataclass(
    frozen=True,
    slots=True,
)
class MachineApiCredential:
    key_sha256: str
    organization_id: UUID
    machine_uid: UUID
    is_active: bool = True

    def __post_init__(
        self,
    ) -> None:
        normalized_hash = (
            self.key_sha256
            .strip()
            .lower()
        )

        if len(normalized_hash) != 64:
            raise ValueError(
                "key_sha256 must be a SHA-256 "
                "hex digest"
            )

        if any(
            character not in "0123456789abcdef"
            for character in normalized_hash
        ):
            raise ValueError(
                "key_sha256 must contain only "
                "hexadecimal characters"
            )

        object.__setattr__(
            self,
            "key_sha256",
            normalized_hash,
        )


@dataclass(
    frozen=True,
    slots=True,
)
class MachinePrincipal:
    organization_id: UUID
    machine_uid: UUID


class MachineApiKeyAuthenticator:
    """
    Authentification machine V1.

    Les clés API brutes ne sont jamais stockées dans
    la configuration serveur : uniquement leur SHA-256.

    Chaque credential est lié à exactement :
        organization_id + machine_uid

    Une clé d'une machine ne peut donc pas choisir
    un autre tenant ni une autre identité machine.
    """

    def __init__(
        self,
        credentials: list[
            MachineApiCredential
        ],
    ) -> None:
        if credentials is None:
            raise ValueError(
                "credentials must not be None"
            )

        self._credentials_by_hash: dict[
            str,
            MachineApiCredential,
        ] = {}

        for credential in credentials:
            existing = (
                self._credentials_by_hash.get(
                    credential.key_sha256
                )
            )

            if existing is not None:
                raise ValueError(
                    "Duplicate machine API "
                    "credential hash"
                )

            self._credentials_by_hash[
                credential.key_sha256
            ] = credential

    def authenticate(
        self,
        api_key: str,
    ) -> MachinePrincipal | None:
        if not isinstance(
            api_key,
            str,
        ):
            return None

        normalized_api_key = (
            api_key.strip()
        )

        if not normalized_api_key:
            return None

        key_hash = self.hash_api_key(
            normalized_api_key
        )

        credential = (
            self._credentials_by_hash.get(
                key_hash
            )
        )

        if (
            credential is None
            or not credential.is_active
        ):
            return None

        return MachinePrincipal(
            organization_id=(
                credential.organization_id
            ),
            machine_uid=(
                credential.machine_uid
            ),
        )

    @staticmethod
    def hash_api_key(
        api_key: str,
    ) -> str:
        if not isinstance(
            api_key,
            str,
        ):
            raise TypeError(
                "api_key must be a string"
            )

        if not api_key:
            raise ValueError(
                "api_key must not be empty"
            )

        return sha256(
            api_key.encode("utf-8")
        ).hexdigest()