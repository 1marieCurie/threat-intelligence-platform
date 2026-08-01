from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from ipaddress import (
    ip_address,
    ip_network,
)
from typing import Any
from urllib.parse import urlsplit
from uuid import UUID

from application.ports.outbound.phishtank_phishing_repository import (
    PhishTankNetworkDetailData,
    PhishTankPhishingData,
)


class PhishTankNormalizationError(
    ValueError
):
    """
    Raised when a raw PhishTank payload is invalid.
    """


class PhishTankNormalizer:
    NORMALIZER_VERSION = "1.0.1"

    _MAX_URL_LENGTH = 4_096
    _MAX_TARGET_LENGTH = 255
    _MAX_NETWORK_DETAILS = 100
    _MAX_NETWORK_VALUE_LENGTH = 255
    _MAX_ANNOUNCING_NETWORK_LENGTH = 64
    _MAX_RIR_LENGTH = 32
    _MAX_HOSTNAME_LENGTH = 253

    _TRUE_VALUES = frozenset(
        {
            "yes",
            "y",
            "true",
            "1",
        }
    )

    _FALSE_VALUES = frozenset(
        {
            "no",
            "n",
            "false",
            "0",
        }
    )

    def normalize(
        self,
        *,
        raw_payload_id: UUID,
        payload: Mapping[str, Any],
    ) -> PhishTankPhishingData:
        if not isinstance(
            raw_payload_id,
            UUID,
        ):
            raise TypeError(
                "raw_payload_id must be a UUID"
            )

        if not isinstance(
            payload,
            Mapping,
        ):
            raise TypeError(
                "payload must be a mapping"
            )

        phish_id = self._required_phish_id(
            payload.get(
                "phish_id"
            )
        )

        phishing_url, hostname = (
            self._required_url(
                payload.get(
                    "url"
                ),
                field_name="url",
            )
        )

        phish_detail_url = (
            self._optional_url(
                payload.get(
                    "phish_detail_url"
                ),
                field_name=(
                    "phish_detail_url"
                ),
            )
        )

        submission_time = (
            self._optional_datetime(
                payload.get(
                    "submission_time"
                ),
                field_name=(
                    "submission_time"
                ),
            )
        )

        verification_time = (
            self._optional_datetime(
                payload.get(
                    "verification_time"
                ),
                field_name=(
                    "verification_time"
                ),
            )
        )

        if (
            submission_time is not None
            and verification_time is not None
            and verification_time
            < submission_time
        ):
            raise PhishTankNormalizationError(
                "verification_time must not "
                "be before submission_time"
            )

        verified = self._optional_boolean(
            payload.get(
                "verified"
            ),
            field_name="verified",
        )

        online = self._optional_boolean(
            payload.get(
                "online"
            ),
            field_name="online",
        )

        target = self._optional_string(
            payload.get(
                "target"
            ),
            field_name="target",
            max_length=(
                self._MAX_TARGET_LENGTH
            ),
        )

        network_details = (
            self._normalize_network_details(
                payload.get(
                    "details"
                )
            )
        )

        return PhishTankPhishingData(
            raw_payload_id=raw_payload_id,
            phish_id=phish_id,
            phishing_url=phishing_url,
            hostname=hostname,
            phish_detail_url=(
                phish_detail_url
            ),
            submission_time=(
                submission_time
            ),
            verification_time=(
                verification_time
            ),
            verified=verified,
            online=online,
            target=target,
            network_details=(
                network_details
            ),
            normalizer_version=(
                self.NORMALIZER_VERSION
            ),
        )

    # ========================================================
    # Required values
    # ========================================================

    @staticmethod
    def _required_phish_id(
        value: Any,
    ) -> int:
        if isinstance(
            value,
            bool,
        ):
            raise PhishTankNormalizationError(
                "phish_id must be a positive integer"
            )

        if isinstance(
            value,
            int,
        ):
            phish_id = value

        elif isinstance(
            value,
            str,
        ):
            normalized = (
                value.strip()
            )

            if (
                not normalized
                or not normalized.isascii()
                or not normalized.isdigit()
            ):
                raise PhishTankNormalizationError(
                    "phish_id must be "
                    "a positive integer"
                )

            phish_id = int(
                normalized
            )

        else:
            raise PhishTankNormalizationError(
                "phish_id must be a positive integer"
            )

        if phish_id <= 0:
            raise PhishTankNormalizationError(
                "phish_id must be a positive integer"
            )

        return phish_id

    @classmethod
    def _required_url(
        cls,
        value: Any,
        *,
        field_name: str,
    ) -> tuple[
        str,
        str,
    ]:
        normalized = cls._required_string(
            value,
            field_name=field_name,
            max_length=(
                cls._MAX_URL_LENGTH
            ),
        )

        hostname = cls._validate_url(
            normalized,
            field_name=field_name,
        )

        return (
            normalized,
            hostname,
        )

    @staticmethod
    def _required_string(
        value: Any,
        *,
        field_name: str,
        max_length: int,
    ) -> str:
        if not isinstance(
            value,
            str,
        ):
            raise PhishTankNormalizationError(
                f"{field_name} must be a string"
            )

        normalized = (
            value
            .replace(
                "\u00a0",
                " ",
            )
            .strip()
        )

        if not normalized:
            raise PhishTankNormalizationError(
                f"{field_name} must not be empty"
            )

        if len(
            normalized
        ) > max_length:
            raise PhishTankNormalizationError(
                f"{field_name} exceeds "
                f"{max_length} characters"
            )

        return normalized

    # ========================================================
    # URL normalization
    # ========================================================

    @classmethod
    def _optional_url(
        cls,
        value: Any,
        *,
        field_name: str,
    ) -> str | None:
        normalized = cls._optional_string(
            value,
            field_name=field_name,
            max_length=(
                cls._MAX_URL_LENGTH
            ),
        )

        if normalized is None:
            return None

        cls._validate_url(
            normalized,
            field_name=field_name,
        )

        return normalized

    @classmethod
    def _validate_url(
        cls,
        value: str,
        *,
        field_name: str,
    ) -> str:
        contains_invalid_character = any(
            character.isspace()
            or ord(character) < 32
            or ord(character) == 127
            for character in value
        )

        if contains_invalid_character:
            raise PhishTankNormalizationError(
                f"{field_name} has an invalid format"
            )

        try:
            parsed = urlsplit(
                value
            )

            hostname = (
                parsed.hostname
            )

            # Accessing port raises ValueError when malformed.
            parsed.port

        except ValueError as error:
            raise PhishTankNormalizationError(
                f"{field_name} has an invalid format"
            ) from error

        if parsed.scheme.lower() not in {
            "http",
            "https",
        }:
            raise PhishTankNormalizationError(
                f"{field_name} must use "
                "http or https"
            )

        if not hostname:
            raise PhishTankNormalizationError(
                f"{field_name} must include "
                "a hostname"
            )

        normalized_hostname = (
            hostname
            .strip()
            .lower()
        )

        if (
            not normalized_hostname
            or len(
                normalized_hostname
            )
            > cls._MAX_HOSTNAME_LENGTH
        ):
            raise PhishTankNormalizationError(
                f"{field_name} has an "
                "invalid hostname"
            )

        return normalized_hostname

    # ========================================================
    # Optional scalar values
    # ========================================================

    @staticmethod
    def _optional_string(
        value: Any,
        *,
        field_name: str,
        max_length: int,
    ) -> str | None:
        if value is None:
            return None

        if not isinstance(
            value,
            str,
        ):
            raise PhishTankNormalizationError(
                f"{field_name} must be a string"
            )

        normalized = (
            value
            .replace(
                "\u00a0",
                " ",
            )
            .strip()
        )

        if not normalized:
            return None

        if len(
            normalized
        ) > max_length:
            raise PhishTankNormalizationError(
                f"{field_name} exceeds "
                f"{max_length} characters"
            )

        return normalized

    @classmethod
    def _optional_boolean(
        cls,
        value: Any,
        *,
        field_name: str,
    ) -> bool | None:
        if value is None:
            return None

        if isinstance(
            value,
            bool,
        ):
            return value

        if not isinstance(
            value,
            str,
        ):
            raise PhishTankNormalizationError(
                f"{field_name} must be a boolean"
            )

        normalized = (
            value
            .strip()
            .lower()
        )

        if not normalized:
            return None

        if normalized in cls._TRUE_VALUES:
            return True

        if normalized in cls._FALSE_VALUES:
            return False

        raise PhishTankNormalizationError(
            f"{field_name} must be a boolean"
        )

    @staticmethod
    def _optional_datetime(
        value: Any,
        *,
        field_name: str,
    ) -> datetime | None:
        if value is None:
            return None

        if not isinstance(
            value,
            str,
        ):
            raise PhishTankNormalizationError(
                f"{field_name} must be a string"
            )

        normalized = (
            value.strip()
        )

        if not normalized:
            return None

        iso_value = (
            normalized[:-1]
            + "+00:00"
            if normalized.endswith(
                "Z"
            )
            else normalized
        )

        try:
            parsed = datetime.fromisoformat(
                iso_value
            )

        except ValueError as error:
            raise PhishTankNormalizationError(
                f"{field_name} must be an "
                "ISO-8601 timestamp"
            ) from error

        if (
            parsed.tzinfo is None
            or parsed.utcoffset()
            is None
        ):
            raise PhishTankNormalizationError(
                f"{field_name} must include "
                "a timezone"
            )

        return parsed.astimezone(
            UTC
        )

    # ========================================================
    # Network details
    # ========================================================

    @classmethod
    def _normalize_network_details(
        cls,
        value: Any,
    ) -> tuple[
        PhishTankNetworkDetailData,
        ...,
    ]:
        if value is None:
            return ()

        if not isinstance(
            value,
            (list, tuple),
        ):
            raise PhishTankNormalizationError(
                "details must be a list"
            )

        # Les détails réseau sont auxiliaires.
        # On borne le travail avant la boucle pour éviter
        # une consommation mémoire/CPU non maîtrisée.
        bounded_items = value[
            :cls._MAX_NETWORK_DETAILS
        ]

        result: list[
            PhishTankNetworkDetailData
        ] = []

        seen: set[
            PhishTankNetworkDetailData
        ] = set()

        for item in bounded_items:
            if not isinstance(
                item,
                Mapping,
            ):
                continue

            detail = (
                cls._normalize_network_detail(
                    item
                )
            )

            if (
                detail is None
                or detail in seen
            ):
                continue

            seen.add(
                detail
            )

            result.append(
                detail
            )

        return tuple(
            result
        )

    @classmethod
    def _normalize_network_detail(
        cls,
        detail: Mapping[str, Any],
    ) -> PhishTankNetworkDetailData | None:
        ip_address_value = (
            cls._normalize_ip_address(
                detail.get(
                    "ip_address"
                )
            )
        )

        cidr_block = (
            cls._normalize_cidr_block(
                detail.get(
                    "cidr_block"
                )
            )
        )

        announcing_network = (
            cls._clean_optional_string(
                detail.get(
                    "announcing_network"
                ),
                field_name=(
                    "announcing_network"
                ),
                max_length=(
                    cls
                    ._MAX_ANNOUNCING_NETWORK_LENGTH
                ),
            )
        )

        rir = cls._clean_optional_string(
            detail.get(
                "rir"
            ),
            field_name="rir",
            max_length=(
                cls._MAX_RIR_LENGTH
            ),
            lowercase=True,
        )

        country = cls._normalize_country(
            detail.get(
                "country"
            )
        )

        detail_time = (
            cls._optional_datetime(
                detail.get(
                    "detail_time"
                ),
                field_name="detail_time",
            )
        )

        normalized = (
            PhishTankNetworkDetailData(
                ip_address=(
                    ip_address_value
                ),
                cidr_block=cidr_block,
                announcing_network=(
                    announcing_network
                ),
                rir=rir,
                country=country,
                detail_time=detail_time,
            )
        )

        if all(
            field is None
            for field in (
                normalized.ip_address,
                normalized.cidr_block,
                normalized.announcing_network,
                normalized.rir,
                normalized.country,
                normalized.detail_time,
            )
        ):
            return None

        return normalized

    @classmethod
    def _normalize_ip_address(
        cls,
        value: Any,
    ) -> str | None:
        normalized = (
            cls._clean_optional_string(
                value,
                field_name="ip_address",
                max_length=(
                    cls
                    ._MAX_NETWORK_VALUE_LENGTH
                ),
            )
        )

        if normalized is None:
            return None

        try:
            return str(
                ip_address(
                    normalized
                )
            )

        except ValueError:
            return None

    @classmethod
    def _normalize_cidr_block(
        cls,
        value: Any,
    ) -> str | None:
        normalized = (
            cls._clean_optional_string(
                value,
                field_name="cidr_block",
                max_length=(
                    cls
                    ._MAX_NETWORK_VALUE_LENGTH
                ),
            )
        )

        if normalized is None:
            return None

        try:
            return str(
                ip_network(
                    normalized,
                    strict=False,
                )
            )

        except ValueError:
            return None

    @classmethod
    def _normalize_country(
        cls,
        value: Any,
    ) -> str | None:
        normalized = (
            cls._clean_optional_string(
                value,
                field_name="country",
                max_length=32,
                uppercase=True,
            )
        )

        if (
            normalized is None
            or len(normalized) != 2
            or not normalized.isascii()
            or not normalized.isalpha()
        ):
            return None

        return normalized

    @staticmethod
    def _clean_optional_string(
        value: Any,
        *,
        field_name: str,
        max_length: int,
        lowercase: bool = False,
        uppercase: bool = False,
    ) -> str | None:
        if (
            value is None
            or not isinstance(
                value,
                str,
            )
        ):
            return None

        normalized = (
            value
            .replace(
                "\u00a0",
                " ",
            )
            .strip()
        )

        if not normalized:
            return None

        if len(
            normalized
        ) > max_length:
            raise PhishTankNormalizationError(
                f"{field_name} exceeds "
                f"{max_length} characters"
            )

        if lowercase:
            return normalized.lower()

        if uppercase:
            return normalized.upper()

        return normalized