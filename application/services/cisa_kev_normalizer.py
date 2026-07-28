from __future__ import annotations

import re
from collections.abc import Mapping
from datetime import date
from typing import Any
from uuid import UUID

from application.ports.outbound.cisa_kev_vulnerability_repository import (
    CisaKevVulnerabilityData,
)


class CisaKevNormalizationError(ValueError):
    """Raised when a raw CISA KEV payload is invalid."""


class CisaKevNormalizer:
    NORMALIZER_VERSION = "1.0.0"

    _CVE_PATTERN = re.compile(
        r"^CVE-\d{4}-\d{4,19}$"
    )

    _CWE_PATTERN = re.compile(
        r"^CWE-\d+$"
    )

    _MAX_CWE_COUNT = 100

    def normalize(
        self,
        *,
        raw_payload_id: UUID,
        payload: Mapping[str, Any],
    ) -> CisaKevVulnerabilityData:
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

        cve_id = self._required_string(
            payload=payload,
            field_name="cveID",
            max_length=32,
        ).upper()

        if not self._CVE_PATTERN.fullmatch(
            cve_id
        ):
            raise CisaKevNormalizationError(
                "cveID has an invalid format"
            )

        vendor_project = self._required_string(
            payload=payload,
            field_name="vendorProject",
            max_length=255,
        )

        product = self._required_string(
            payload=payload,
            field_name="product",
            max_length=255,
        )

        vulnerability_name = (
            self._required_string(
                payload=payload,
                field_name="vulnerabilityName",
                max_length=1_000,
            )
        )

        date_added = self._required_date(
            payload=payload,
            field_name="dateAdded",
        )

        short_description = (
            self._required_string(
                payload=payload,
                field_name="shortDescription",
                max_length=5_000,
            )
        )

        required_action = (
            self._required_string(
                payload=payload,
                field_name="requiredAction",
                max_length=5_000,
            )
        )

        due_date = self._required_date(
            payload=payload,
            field_name="dueDate",
        )

        if due_date < date_added:
            raise CisaKevNormalizationError(
                "dueDate must not be before dateAdded"
            )

        ransomware_use = (
            self._normalize_ransomware_use(
                payload.get(
                    "knownRansomwareCampaignUse"
                )
            )
        )

        notes = self._optional_string(
            payload=payload,
            field_name="notes",
            max_length=10_000,
        )

        cwes = self._normalize_cwes(
            payload.get("cwes")
        )

        return CisaKevVulnerabilityData(
            raw_payload_id=raw_payload_id,
            cve_id=cve_id,
            vendor_project=vendor_project,
            product=product,
            vulnerability_name=(
                vulnerability_name
            ),
            date_added=date_added,
            short_description=(
                short_description
            ),
            required_action=required_action,
            due_date=due_date,
            known_ransomware_campaign_use=(
                ransomware_use
            ),
            notes=notes,
            cwes=cwes,
            normalizer_version=(
                self.NORMALIZER_VERSION
            ),
        )

    @staticmethod
    def _required_string(
        *,
        payload: Mapping[str, Any],
        field_name: str,
        max_length: int,
    ) -> str:
        value = payload.get(field_name)

        if not isinstance(value, str):
            raise CisaKevNormalizationError(
                f"{field_name} must be a string"
            )

        normalized = value.strip()

        if not normalized:
            raise CisaKevNormalizationError(
                f"{field_name} must not be empty"
            )

        if len(normalized) > max_length:
            raise CisaKevNormalizationError(
                f"{field_name} exceeds "
                f"{max_length} characters"
            )

        return normalized

    @staticmethod
    def _optional_string(
        *,
        payload: Mapping[str, Any],
        field_name: str,
        max_length: int,
    ) -> str | None:
        value = payload.get(field_name)

        if value is None:
            return None

        if not isinstance(value, str):
            raise CisaKevNormalizationError(
                f"{field_name} must be a string"
            )

        normalized = value.strip()

        if not normalized:
            return None

        if len(normalized) > max_length:
            raise CisaKevNormalizationError(
                f"{field_name} exceeds "
                f"{max_length} characters"
            )

        return normalized

    @staticmethod
    def _required_date(
        *,
        payload: Mapping[str, Any],
        field_name: str,
    ) -> date:
        value = payload.get(field_name)

        if not isinstance(value, str):
            raise CisaKevNormalizationError(
                f"{field_name} must be a string"
            )

        normalized = value.strip()

        try:
            parsed_date = date.fromisoformat(
                normalized
            )
        except ValueError as error:
            raise CisaKevNormalizationError(
                f"{field_name} must use "
                "the YYYY-MM-DD format"
            ) from error

        if parsed_date.isoformat() != normalized:
            raise CisaKevNormalizationError(
                f"{field_name} must use "
                "the YYYY-MM-DD format"
            )

        return parsed_date

    @staticmethod
    def _normalize_ransomware_use(
        value: Any,
    ) -> str:
        if not isinstance(value, str):
            raise CisaKevNormalizationError(
                "knownRansomwareCampaignUse "
                "must be a string"
            )

        normalized = value.strip().lower()

        if normalized not in {
            "known",
            "unknown",
        }:
            raise CisaKevNormalizationError(
                "knownRansomwareCampaignUse "
                "must be Known or Unknown"
            )

        return normalized

    @classmethod
    def _normalize_cwes(
        cls,
        value: Any,
    ) -> tuple[str, ...]:
        if value is None:
            return ()

        if not isinstance(
            value,
            (list, tuple),
        ):
            raise CisaKevNormalizationError(
                "cwes must be a list"
            )

        if len(value) > cls._MAX_CWE_COUNT:
            raise CisaKevNormalizationError(
                "cwes contains too many values"
            )

        normalized_cwes: list[str] = []
        seen: set[str] = set()

        for item in value:
            if not isinstance(item, str):
                raise CisaKevNormalizationError(
                    "each CWE must be a string"
                )

            cwe = item.strip().upper()

            if not cls._CWE_PATTERN.fullmatch(
                cwe
            ):
                raise CisaKevNormalizationError(
                    f"invalid CWE identifier: {cwe}"
                )

            if cwe not in seen:
                seen.add(cwe)
                normalized_cwes.append(cwe)

        return tuple(normalized_cwes)