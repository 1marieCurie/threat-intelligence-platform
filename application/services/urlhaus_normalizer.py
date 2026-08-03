from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from itertools import islice
from typing import Any
from urllib.parse import urlsplit
from uuid import UUID

from application.ports.outbound.urlhaus_url_repository import (
    URLhausBlacklistData,
    URLhausURLData,
)


class URLhausNormalizationError(
    ValueError
):
    """
    Raised when a raw URLhaus payload cannot be normalized.

    Error messages contain field names only. Raw IOC values,
    URLs and provider content must never be included.
    """


class URLhausNormalizer:
    """
    Pure URLhaus summary-record normalizer.

    The normalizer performs:

    - deterministic validation;
    - bounded collection processing;
    - URL and hostname validation;
    - UTC datetime conversion;
    - scalar normalization.

    It performs no HTTP request, DNS resolution, logging,
    persistence or transaction management.
    """

    NORMALIZER_VERSION = "1.0.0"

    _MAX_URL_LENGTH = 4_096
    _MAX_HOSTNAME_LENGTH = 253
    _MAX_STATUS_LENGTH = 32
    _MAX_THREAT_LENGTH = 100
    _MAX_REPORTER_LENGTH = 255

    _MAX_TAGS = 100
    _MAX_TAG_LENGTH = 100

    _MAX_BLACKLISTS = 50
    _MAX_BLACKLIST_NAME_LENGTH = 100
    _MAX_BLACKLIST_STATUS_LENGTH = 100

    _TRUE_VALUES = frozenset(
        {
            "true",
            "yes",
            "y",
            "1",
        }
    )

    _FALSE_VALUES = frozenset(
        {
            "false",
            "no",
            "n",
            "0",
        }
    )

    def normalize(
        self,
        *,
        raw_payload_id: UUID,
        payload: Mapping[str, Any],
    ) -> URLhausURLData:
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

        urlhaus_id = (
            self._required_positive_integer(
                payload.get("id"),
                field_name="id",
            )
        )

        malicious_url, hostname = (
            self._required_url(
                payload.get("url"),
                field_name="url",
            )
        )

        reported_host = (
            self._optional_host(
                payload.get("host")
            )
        )

        if (
            reported_host is not None
            and reported_host != hostname
        ):
            raise URLhausNormalizationError(
                "host must match the URL hostname"
            )

        urlhaus_reference = (
            self._optional_url(
                payload.get(
                    "urlhaus_reference"
                ),
                field_name=(
                    "urlhaus_reference"
                ),
            )
        )

        url_status = (
            self._optional_string(
                payload.get(
                    "url_status"
                ),
                field_name="url_status",
                max_length=(
                    self._MAX_STATUS_LENGTH
                ),
                lowercase=True,
            )
        )

        date_added = (
            self._optional_datetime(
                payload.get(
                    "date_added"
                ),
                field_name="date_added",
            )
        )

        threat_type = (
            self._optional_string(
                payload.get("threat"),
                field_name="threat",
                max_length=(
                    self._MAX_THREAT_LENGTH
                ),
                lowercase=True,
            )
        )

        reporter = (
            self._optional_string(
                payload.get("reporter"),
                field_name="reporter",
                max_length=(
                    self._MAX_REPORTER_LENGTH
                ),
            )
        )

        larted = self._optional_boolean(
            payload.get("larted"),
            field_name="larted",
        )

        tags = self._normalize_tags(
            payload.get("tags")
        )

        blacklists = (
            self._normalize_blacklists(
                payload.get(
                    "blacklists"
                )
            )
        )

        return URLhausURLData(
            raw_payload_id=raw_payload_id,
            urlhaus_id=urlhaus_id,
            malicious_url=malicious_url,
            hostname=hostname,
            urlhaus_reference=(
                urlhaus_reference
            ),
            url_status=url_status,
            date_added=date_added,
            threat_type=threat_type,
            reporter=reporter,
            larted=larted,
            tags=tags,
            blacklists=blacklists,
            normalizer_version=(
                self.NORMALIZER_VERSION
            ),
        )

    # ========================================================
    # Required values
    # ========================================================

    @staticmethod
    def _required_positive_integer(
        value: Any,
        *,
        field_name: str,
    ) -> int:
        if isinstance(
            value,
            bool,
        ):
            raise URLhausNormalizationError(
                f"{field_name} must be "
                "a positive integer"
            )

        if isinstance(
            value,
            int,
        ):
            parsed_value = value

        elif isinstance(
            value,
            str,
        ):
            normalized_value = (
                value.strip()
            )

            if (
                not normalized_value
                or not normalized_value.isascii()
                or not normalized_value.isdigit()
            ):
                raise URLhausNormalizationError(
                    f"{field_name} must be "
                    "a positive integer"
                )

            parsed_value = int(
                normalized_value
            )

        else:
            raise URLhausNormalizationError(
                f"{field_name} must be "
                "a positive integer"
            )

        if parsed_value <= 0:
            raise URLhausNormalizationError(
                f"{field_name} must be "
                "a positive integer"
            )

        return parsed_value

    @classmethod
    def _required_url(
        cls,
        value: Any,
        *,
        field_name: str,
    ) -> tuple[str, str]:
        normalized_value = (
            cls._required_string(
                value,
                field_name=field_name,
                max_length=(
                    cls._MAX_URL_LENGTH
                ),
            )
        )

        hostname = cls._validate_url(
            normalized_value,
            field_name=field_name,
        )

        return (
            normalized_value,
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
            raise URLhausNormalizationError(
                f"{field_name} must be a string"
            )

        normalized_value = (
            value
            .replace("\u00a0", " ")
            .strip()
        )

        if not normalized_value:
            raise URLhausNormalizationError(
                f"{field_name} must not be empty"
            )

        if (
            len(normalized_value)
            > max_length
        ):
            raise URLhausNormalizationError(
                f"{field_name} exceeds "
                f"{max_length} characters"
            )

        return normalized_value

    # ========================================================
    # URL and host validation
    # ========================================================

    @classmethod
    def _optional_url(
        cls,
        value: Any,
        *,
        field_name: str,
    ) -> str | None:
        normalized_value = (
            cls._optional_string(
                value,
                field_name=field_name,
                max_length=(
                    cls._MAX_URL_LENGTH
                ),
            )
        )

        if normalized_value is None:
            return None

        cls._validate_url(
            normalized_value,
            field_name=field_name,
        )

        return normalized_value

    @classmethod
    def _validate_url(
        cls,
        value: str,
        *,
        field_name: str,
    ) -> str:
        if any(
            character.isspace()
            or ord(character) < 32
            or ord(character) == 127
            for character in value
        ):
            raise URLhausNormalizationError(
                f"{field_name} has an "
                "invalid format"
            )

        try:
            parsed_url = urlsplit(
                value
            )

            hostname = (
                parsed_url.hostname
            )

            # Access validates malformed ports.
            parsed_url.port

        except ValueError as error:
            raise URLhausNormalizationError(
                f"{field_name} has an "
                "invalid format"
            ) from error

        if parsed_url.scheme.lower() not in {
            "http",
            "https",
        }:
            raise URLhausNormalizationError(
                f"{field_name} must use "
                "http or https"
            )

        if not hostname:
            raise URLhausNormalizationError(
                f"{field_name} must include "
                "a hostname"
            )

        normalized_hostname = (
            hostname
            .strip()
            .lower()
            .rstrip(".")
        )

        if (
            not normalized_hostname
            or len(normalized_hostname)
            > cls._MAX_HOSTNAME_LENGTH
        ):
            raise URLhausNormalizationError(
                f"{field_name} has an "
                "invalid hostname"
            )

        return normalized_hostname

    @classmethod
    def _optional_host(
        cls,
        value: Any,
    ) -> str | None:
        normalized_value = (
            cls._optional_string(
                value,
                field_name="host",
                max_length=(
                    cls._MAX_HOSTNAME_LENGTH
                ),
            )
        )

        if normalized_value is None:
            return None

        if any(
            character.isspace()
            or ord(character) < 32
            or ord(character) == 127
            for character in normalized_value
        ):
            raise URLhausNormalizationError(
                "host has an invalid format"
            )

        try:
            parsed_host = urlsplit(
                f"//{normalized_value}"
            )

            hostname = parsed_host.hostname
            parsed_host.port

        except ValueError as error:
            raise URLhausNormalizationError(
                "host has an invalid format"
            ) from error

        if not hostname:
            raise URLhausNormalizationError(
                "host has an invalid format"
            )

        normalized_hostname = (
            hostname
            .strip()
            .lower()
            .rstrip(".")
        )

        if (
            not normalized_hostname
            or len(normalized_hostname)
            > cls._MAX_HOSTNAME_LENGTH
        ):
            raise URLhausNormalizationError(
                "host has an invalid format"
            )

        return normalized_hostname

    # ========================================================
    # Scalar values
    # ========================================================

    @staticmethod
    def _optional_string(
        value: Any,
        *,
        field_name: str,
        max_length: int,
        lowercase: bool = False,
    ) -> str | None:
        if value is None:
            return None

        if not isinstance(
            value,
            str,
        ):
            raise URLhausNormalizationError(
                f"{field_name} must be a string"
            )

        normalized_value = (
            value
            .replace("\u00a0", " ")
            .strip()
        )

        if not normalized_value:
            return None

        if (
            len(normalized_value)
            > max_length
        ):
            raise URLhausNormalizationError(
                f"{field_name} exceeds "
                f"{max_length} characters"
            )

        if lowercase:
            return normalized_value.lower()

        return normalized_value

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
            raise URLhausNormalizationError(
                f"{field_name} must be "
                "a boolean"
            )

        normalized_value = (
            value.strip().lower()
        )

        if not normalized_value:
            return None

        if normalized_value in (
            cls._TRUE_VALUES
        ):
            return True

        if normalized_value in (
            cls._FALSE_VALUES
        ):
            return False

        raise URLhausNormalizationError(
            f"{field_name} must be "
            "a boolean"
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
            raise URLhausNormalizationError(
                f"{field_name} must be "
                "a string"
            )

        normalized_value = (
            value.strip()
        )

        if not normalized_value:
            return None

        try:
            if normalized_value.endswith(
                " UTC"
            ):
                parsed_value = (
                    datetime.strptime(
                        normalized_value,
                        "%Y-%m-%d %H:%M:%S UTC",
                    )
                    .replace(
                        tzinfo=UTC
                    )
                )

            else:
                iso_value = (
                    normalized_value[:-1]
                    + "+00:00"
                    if normalized_value.endswith(
                        "Z"
                    )
                    else normalized_value
                )

                parsed_value = (
                    datetime.fromisoformat(
                        iso_value
                    )
                )

        except ValueError as error:
            raise URLhausNormalizationError(
                f"{field_name} must be "
                "a valid timestamp"
            ) from error

        if (
            parsed_value.tzinfo is None
            or parsed_value.utcoffset()
            is None
        ):
            raise URLhausNormalizationError(
                f"{field_name} must include "
                "a timezone"
            )

        return parsed_value.astimezone(
            UTC
        )

    # ========================================================
    # Bounded auxiliary collections
    # ========================================================

    @classmethod
    def _normalize_tags(
        cls,
        value: Any,
    ) -> tuple[str, ...]:
        if value is None:
            return ()

        if not isinstance(
            value,
            (list, tuple),
        ):
            raise URLhausNormalizationError(
                "tags must be a list"
            )

        normalized_tags: list[
            str
        ] = []

        seen: set[str] = set()

        for item in islice(
            value,
            cls._MAX_TAGS,
        ):
            normalized_item = (
                cls._clean_auxiliary_string(
                    item,
                    max_length=(
                        cls._MAX_TAG_LENGTH
                    ),
                    lowercase=True,
                )
            )

            if (
                normalized_item is None
                or normalized_item in seen
            ):
                continue

            seen.add(
                normalized_item
            )

            normalized_tags.append(
                normalized_item
            )

        return tuple(
            normalized_tags
        )

    @classmethod
    def _normalize_blacklists(
        cls,
        value: Any,
    ) -> tuple[
        URLhausBlacklistData,
        ...,
    ]:
        if value is None:
            return ()

        if not isinstance(
            value,
            Mapping,
        ):
            raise URLhausNormalizationError(
                "blacklists must be a mapping"
            )

        normalized_blacklists: list[
            URLhausBlacklistData
        ] = []

        seen_names: set[str] = set()

        for raw_name, raw_status in islice(
            value.items(),
            cls._MAX_BLACKLISTS,
        ):
            name = (
                cls._clean_auxiliary_string(
                    raw_name,
                    max_length=(
                        cls
                        ._MAX_BLACKLIST_NAME_LENGTH
                    ),
                    lowercase=True,
                )
            )

            status = (
                cls._clean_auxiliary_string(
                    raw_status,
                    max_length=(
                        cls
                        ._MAX_BLACKLIST_STATUS_LENGTH
                    ),
                    lowercase=True,
                )
            )

            if (
                name is None
                or status is None
                or name in seen_names
            ):
                continue

            seen_names.add(
                name
            )

            normalized_blacklists.append(
                URLhausBlacklistData(
                    name=name,
                    status=status,
                )
            )

        normalized_blacklists.sort(
            key=lambda blacklist: (
                blacklist.name
            )
        )

        return tuple(
            normalized_blacklists
        )

    @staticmethod
    def _clean_auxiliary_string(
        value: Any,
        *,
        max_length: int,
        lowercase: bool,
    ) -> str | None:
        """
        Auxiliary collection entries are best-effort.

        A malformed tag or blacklist entry does not invalidate the
        complete URLhaus record.
        """

        if not isinstance(
            value,
            str,
        ):
            return None

        normalized_value = (
            value
            .replace("\u00a0", " ")
            .strip()
        )

        if (
            not normalized_value
            or len(normalized_value)
            > max_length
        ):
            return None

        if lowercase:
            return normalized_value.lower()

        return normalized_value