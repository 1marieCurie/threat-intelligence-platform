from __future__ import annotations

import re
from collections import deque
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit
from uuid import UUID

from application.ports.outbound.github_advisory_vulnerability_repository import (
    GitHubAdvisoryAffectedPackageData,
    GitHubAdvisoryCvssMetricData,
    GitHubAdvisoryVulnerabilityData,
)


class GitHubAdvisoryNormalizationError(
    ValueError
):
    """
    Raised when a raw GitHub advisory cannot be normalized.
    """


class GitHubAdvisoryNormalizer:
    NORMALIZER_VERSION = "1.0.0"

    _GHSA_PATTERN = re.compile(
        r"^GHSA-[A-Z0-9]{4}-"
        r"[A-Z0-9]{4}-"
        r"[A-Z0-9]{4}$",
        re.IGNORECASE,
    )

    _CVE_PATTERN = re.compile(
        r"^CVE-\d{4}-\d{4,19}$",
        re.IGNORECASE,
    )

    _CWE_PATTERN = re.compile(
        r"^CWE-(\d+)$",
        re.IGNORECASE,
    )

    _CWE_PLACEHOLDERS = {
        "NVD-CWE-NOINFO",
        "NVD-CWE-OTHER",
        "CWE-NOINFO",
        "CWE-OTHER",
    }

    _MAX_IDENTIFIERS = 100
    _MAX_VULNERABILITIES = 1_000
    _MAX_VULNERABLE_FUNCTIONS = 500
    _MAX_CWES = 100
    _MAX_REFERENCES = 1_000
    _MAX_SOURCE_LOCATIONS = 1_000
    _MAX_LOCATION_NODES = 4_000

    def normalize(
        self,
        *,
        raw_payload_id: UUID,
        payload: Mapping[str, Any],
    ) -> GitHubAdvisoryVulnerabilityData:
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

        cvss_metrics = (
            self._extract_cvss_metrics(
                payload
            )
        )

        epss_score, epss_percentile = (
            self._extract_epss(
                payload
            )
        )

        return GitHubAdvisoryVulnerabilityData(
            raw_payload_id=raw_payload_id,
            ghsa_id=self._required_ghsa_id(
                payload.get("ghsa_id")
            ),
            cve_id=self._extract_cve_id(
                payload
            ),
            advisory_type=self._optional_string(
                payload.get("type"),
                field_name="type",
                max_length=50,
                transform=str.lower,
            ),
            severity=self._optional_string(
                payload.get("severity"),
                field_name="severity",
                max_length=20,
                transform=str.upper,
            ),
            summary=self._optional_string(
                payload.get("summary"),
                field_name="summary",
                max_length=2_000,
            ),
            description=self._optional_string(
                payload.get("description"),
                field_name="description",
                max_length=100_000,
            ),
            published_at=self._optional_datetime(
                payload.get("published_at"),
                field_name="published_at",
            ),
            updated_at=self._optional_datetime(
                payload.get("updated_at"),
                field_name="updated_at",
            ),
            reviewed_at=self._optional_datetime(
                payload.get(
                    "github_reviewed_at"
                ),
                field_name=(
                    "github_reviewed_at"
                ),
            ),
            withdrawn_at=self._optional_datetime(
                payload.get("withdrawn_at"),
                field_name="withdrawn_at",
            ),
            cvss_score=(
                self._select_primary_cvss_score(
                    cvss_metrics
                )
            ),
            cvss_metrics=cvss_metrics,
            epss_score=epss_score,
            epss_percentile=epss_percentile,
            affected_packages=(
                self._extract_affected_packages(
                    payload
                )
            ),
            cwe_ids=self._extract_cwe_ids(
                payload
            ),
            references=self._extract_references(
                payload
            ),
            api_url=self._normalize_url(
                payload.get("url")
            ),
            html_url=self._normalize_url(
                payload.get("html_url")
            ),
            repository_advisory_url=(
                self._normalize_url(
                    payload.get(
                        "repository_advisory_url"
                    )
                )
            ),
            source_code_locations=(
                self._extract_source_locations(
                    payload
                )
            ),
            normalizer_version=(
                self.NORMALIZER_VERSION
            ),
        )

    @classmethod
    def _required_ghsa_id(
        cls,
        value: Any,
    ) -> str:
        if not isinstance(value, str):
            raise (
                GitHubAdvisoryNormalizationError(
                    "ghsa_id must be a string"
                )
            )

        normalized = value.strip()

        if not cls._GHSA_PATTERN.fullmatch(
            normalized
        ):
            raise (
                GitHubAdvisoryNormalizationError(
                    "ghsa_id has an invalid format"
                )
            )

        _, first, second, third = (
            normalized.split("-")
        )

        return (
            "GHSA-"
            f"{first.lower()}-"
            f"{second.lower()}-"
            f"{third.lower()}"
        )

    @classmethod
    def _extract_cve_id(
        cls,
        payload: Mapping[str, Any],
    ) -> str | None:
        direct_value = payload.get(
            "cve_id"
        )

        if direct_value is not None:
            cve_id = cls._normalize_cve_id(
                direct_value
            )

            if cve_id is None:
                raise (
                    GitHubAdvisoryNormalizationError(
                        "cve_id has an "
                        "invalid format"
                    )
                )

            return cve_id

        identifiers = payload.get(
            "identifiers"
        )

        if identifiers is None:
            return None

        cls._require_bounded_list(
            identifiers,
            field_name="identifiers",
            max_count=cls._MAX_IDENTIFIERS,
        )

        for identifier in identifiers:
            if not isinstance(
                identifier,
                Mapping,
            ):
                continue

            identifier_type = (
                cls._clean_string(
                    identifier.get("type")
                )
            )

            if (
                identifier_type is None
                or identifier_type.upper()
                != "CVE"
            ):
                continue

            cve_id = cls._normalize_cve_id(
                identifier.get("value")
            )

            if cve_id is not None:
                return cve_id

        return None

    @classmethod
    def _normalize_cve_id(
        cls,
        value: Any,
    ) -> str | None:
        normalized = cls._clean_string(
            value
        )

        if (
            normalized is None
            or not cls._CVE_PATTERN.fullmatch(
                normalized
            )
        ):
            return None

        return normalized.upper()

    @classmethod
    def _extract_cvss_metrics(
        cls,
        payload: Mapping[str, Any],
    ) -> tuple[
        GitHubAdvisoryCvssMetricData,
        ...,
    ]:
        metrics: dict[
            str,
            GitHubAdvisoryCvssMetricData,
        ] = {}

        severities = payload.get(
            "cvss_severities"
        )

        if isinstance(
            severities,
            Mapping,
        ):
            cls._add_cvss_metric(
                metrics,
                fallback_version="3",
                data=severities.get(
                    "cvss_v3"
                ),
            )

            cls._add_cvss_metric(
                metrics,
                fallback_version="4",
                data=severities.get(
                    "cvss_v4"
                ),
            )

        has_v3 = any(
            version.startswith("3")
            for version in metrics
        )

        legacy_cvss = payload.get(
            "cvss"
        )

        if (
            isinstance(
                legacy_cvss,
                Mapping,
            )
            and not has_v3
        ):
            cls._add_cvss_metric(
                metrics,
                fallback_version="3",
                data=legacy_cvss,
            )

        return tuple(
            metrics.values()
        )

    @classmethod
    def _add_cvss_metric(
        cls,
        metrics: dict[
            str,
            GitHubAdvisoryCvssMetricData,
        ],
        *,
        fallback_version: str,
        data: Any,
    ) -> None:
        if not isinstance(
            data,
            Mapping,
        ):
            return

        score = cls._bounded_float(
            data.get("score"),
            minimum=0.0,
            maximum=10.0,
        )

        vector = cls._clean_string(
            data.get("vector_string"),
            max_length=255,
        )

        if (
            score is None
            and vector is None
        ):
            return

        if (
            score == 0.0
            and vector is None
        ):
            return

        version = (
            cls._extract_cvss_version(
                vector
            )
            or fallback_version
        )

        metrics[version] = (
            GitHubAdvisoryCvssMetricData(
                version=version,
                score=score,
                vector=vector,
            )
        )

    @staticmethod
    def _extract_cvss_version(
        vector: str | None,
    ) -> str | None:
        if (
            vector is None
            or not vector.upper().startswith(
                "CVSS:"
            )
        ):
            return None

        prefix = vector.split(
            "/",
            1,
        )[0]

        _, separator, version = (
            prefix.partition(":")
        )

        if not separator:
            return None

        return (
            version.strip()
            or None
        )

    @staticmethod
    def _select_primary_cvss_score(
        metrics: tuple[
            GitHubAdvisoryCvssMetricData,
            ...,
        ],
    ) -> float | None:
        def priority(
            metric: (
                GitHubAdvisoryCvssMetricData
            ),
        ) -> int:
            if metric.version.startswith(
                "4"
            ):
                return 0

            if metric.version.startswith(
                "3"
            ):
                return 1

            return 2

        zero_score: float | None = None

        for metric in sorted(
            metrics,
            key=priority,
        ):
            if metric.score is None:
                continue

            if metric.score > 0.0:
                return metric.score

            zero_score = metric.score

        return zero_score

    @classmethod
    def _extract_epss(
        cls,
        payload: Mapping[str, Any],
    ) -> tuple[
        float | None,
        float | None,
    ]:
        epss = payload.get("epss")

        if not isinstance(
            epss,
            Mapping,
        ):
            return None, None

        return (
            cls._bounded_float(
                epss.get("percentage"),
                minimum=0.0,
                maximum=1.0,
            ),
            cls._bounded_float(
                epss.get("percentile"),
                minimum=0.0,
                maximum=1.0,
            ),
        )

    @classmethod
    def _extract_affected_packages(
        cls,
        payload: Mapping[str, Any],
    ) -> tuple[
        GitHubAdvisoryAffectedPackageData,
        ...,
    ]:
        vulnerabilities = payload.get(
            "vulnerabilities"
        )

        if vulnerabilities is None:
            return ()

        cls._require_bounded_list(
            vulnerabilities,
            field_name="vulnerabilities",
            max_count=(
                cls._MAX_VULNERABILITIES
            ),
        )

        result: list[
            GitHubAdvisoryAffectedPackageData
        ] = []

        seen: set[
            GitHubAdvisoryAffectedPackageData
        ] = set()

        for vulnerability in vulnerabilities:
            if not isinstance(
                vulnerability,
                Mapping,
            ):
                continue

            package = vulnerability.get(
                "package"
            )

            ecosystem: str | None = None
            package_name: str | None = None

            if isinstance(
                package,
                Mapping,
            ):
                ecosystem = cls._clean_string(
                    package.get("ecosystem"),
                    max_length=100,
                )

                package_name = (
                    cls._clean_string(
                        package.get("name"),
                        max_length=1_000,
                    )
                )

            normalized = (
                GitHubAdvisoryAffectedPackageData(
                    ecosystem=ecosystem,
                    package_name=package_name,
                    vulnerable_version_range=(
                        cls._clean_string(
                            vulnerability.get(
                                "vulnerable_version_range"
                            ),
                            max_length=4_000,
                        )
                    ),
                    first_patched_version=(
                        cls._extract_first_patched_version(
                            vulnerability.get(
                                "first_patched_version"
                            )
                        )
                    ),
                    vulnerable_functions=(
                        cls._extract_string_list(
                            vulnerability.get(
                                "vulnerable_functions"
                            ),
                            field_name=(
                                "vulnerable_functions"
                            ),
                            max_count=(
                                cls
                                ._MAX_VULNERABLE_FUNCTIONS
                            ),
                            max_length=2_000,
                        )
                    ),
                    source_code_locations=(
                        cls._flatten_source_locations(
                            vulnerability.get(
                                "source_code_location"
                            )
                        )
                    ),
                )
            )

            if not any(
                (
                    normalized.ecosystem,
                    normalized.package_name,
                    normalized
                    .vulnerable_version_range,
                    normalized
                    .first_patched_version,
                    normalized
                    .vulnerable_functions,
                    normalized
                    .source_code_locations,
                )
            ):
                continue

            if normalized in seen:
                continue

            seen.add(normalized)
            result.append(normalized)

        return tuple(result)

    @classmethod
    def _extract_first_patched_version(
        cls,
        value: Any,
    ) -> str | None:
        if isinstance(
            value,
            Mapping,
        ):
            value = value.get(
                "identifier"
            )

        return cls._clean_string(
            value,
            max_length=255,
        )

    @classmethod
    def _extract_cwe_ids(
        cls,
        payload: Mapping[str, Any],
    ) -> tuple[str, ...]:
        cwes = payload.get("cwes")

        if cwes is None:
            return ()

        cls._require_bounded_list(
            cwes,
            field_name="cwes",
            max_count=cls._MAX_CWES,
        )

        result: list[str] = []
        seen: set[str] = set()

        for item in cwes:
            value = (
                item.get("cwe_id")
                if isinstance(
                    item,
                    Mapping,
                )
                else item
            )

            if isinstance(value, str):
                cleaned = cls._clean_string(
                    value,
                    max_length=500,
                )

                if cleaned is None:
                    continue

                if (
                    cleaned.upper()
                    in cls._CWE_PLACEHOLDERS
                ):
                    continue

                cwe_id = (
                    cls._normalize_cwe_id(
                        cleaned
                    )
                    or cls._extract_cwe_id_from_text(
                        cleaned
                    )
                )

            else:
                cwe_id = cls._normalize_cwe_id(
                    value
                )

            if (
                cwe_id is not None
                and cwe_id not in seen
            ):
                seen.add(cwe_id)
                result.append(cwe_id)

        return tuple(result)

    @classmethod
    def _normalize_cwe_id(
        cls,
        value: Any,
    ) -> str | None:
        if isinstance(value, bool):
            return None

        if isinstance(value, int):
            return (
                f"CWE-{value}"
                if value > 0
                else None
            )

        normalized = cls._clean_string(
            value,
            max_length=500,
        )

        if normalized is None:
            return None

        match = cls._CWE_PATTERN.fullmatch(
            normalized
        )

        numeric_part = (
            match.group(1)
            if match
            else normalized
        )

        if not numeric_part.isdigit():
            return None

        number = int(numeric_part)

        return (
            f"CWE-{number}"
            if number > 0
            else None
        )

    @classmethod
    def _extract_cwe_id_from_text(
        cls,
        value: str,
    ) -> str | None:
        tokens = re.split(
            r"[\s,:()\[\]]+",
            value,
        )

        for token in tokens:
            cwe_id = cls._normalize_cwe_id(
                token
            )

            if cwe_id is not None:
                return cwe_id

        return None

    @classmethod
    def _extract_references(
        cls,
        payload: Mapping[str, Any],
    ) -> tuple[str, ...]:
        references = payload.get(
            "references"
        )

        if references is None:
            return ()

        cls._require_bounded_list(
            references,
            field_name="references",
            max_count=cls._MAX_REFERENCES,
        )

        result: list[str] = []
        seen: set[str] = set()

        for reference in references:
            value = (
                reference.get("url")
                if isinstance(
                    reference,
                    Mapping,
                )
                else reference
            )

            url = cls._normalize_url(
                value
            )

            if (
                url is not None
                and url not in seen
            ):
                seen.add(url)
                result.append(url)

        return tuple(result)

    @classmethod
    def _extract_source_locations(
        cls,
        payload: Mapping[str, Any],
    ) -> tuple[str, ...]:
        candidates: list[Any] = [
            payload.get(
                "source_code_location"
            )
        ]

        vulnerabilities = payload.get(
            "vulnerabilities"
        )

        if isinstance(
            vulnerabilities,
            list,
        ):
            candidates.extend(
                item.get(
                    "source_code_location"
                )
                for item in vulnerabilities
                if isinstance(
                    item,
                    Mapping,
                )
            )

        result: list[str] = []
        seen: set[str] = set()

        for candidate in candidates:
            for location in (
                cls._flatten_source_locations(
                    candidate
                )
            ):
                if location in seen:
                    continue

                seen.add(location)
                result.append(location)

                if (
                    len(result)
                    >= cls._MAX_SOURCE_LOCATIONS
                ):
                    return tuple(result)

        return tuple(result)

    @classmethod
    def _flatten_source_locations(
        cls,
        value: Any,
    ) -> tuple[str, ...]:
        queue: deque[Any] = deque(
            [value]
        )

        result: list[str] = []
        seen: set[str] = set()
        visited_nodes = 0

        while queue:
            visited_nodes += 1

            if (
                visited_nodes
                > cls._MAX_LOCATION_NODES
            ):
                raise (
                    GitHubAdvisoryNormalizationError(
                        "source_code_location is "
                        "too deeply nested"
                    )
                )

            current = queue.popleft()

            if isinstance(current, str):
                location = cls._clean_string(
                    current,
                    max_length=4_096,
                )

                if (
                    location is not None
                    and location not in seen
                ):
                    seen.add(location)
                    result.append(location)

                    if (
                        len(result)
                        >= cls._MAX_SOURCE_LOCATIONS
                    ):
                        return tuple(result)

            elif isinstance(current, list):
                queue.extend(current)

            elif isinstance(
                current,
                Mapping,
            ):
                queue.extend(
                    current[key]
                    for key in (
                        "url",
                        "path",
                        "location",
                    )
                    if current.get(key)
                    is not None
                )

        return tuple(result)

    @staticmethod
    def _optional_datetime(
        value: Any,
        *,
        field_name: str,
    ) -> datetime | None:
        if value is None:
            return None

        if not isinstance(value, str):
            raise (
                GitHubAdvisoryNormalizationError(
                    f"{field_name} must be "
                    "a string"
                )
            )

        normalized = value.strip()

        if not normalized:
            return None

        iso_value = (
            normalized[:-1]
            + "+00:00"
            if normalized.endswith("Z")
            else normalized
        )

        try:
            parsed = datetime.fromisoformat(
                iso_value
            )

        except ValueError as error:
            raise (
                GitHubAdvisoryNormalizationError(
                    f"{field_name} must be an "
                    "ISO-8601 timestamp"
                )
            ) from error

        if parsed.tzinfo is None:
            raise (
                GitHubAdvisoryNormalizationError(
                    f"{field_name} must "
                    "include a timezone"
                )
            )

        return parsed.astimezone(UTC)

    @staticmethod
    def _optional_string(
        value: Any,
        *,
        field_name: str,
        max_length: int,
        transform: Callable[
            [str],
            str,
        ] | None = None,
    ) -> str | None:
        if value is None:
            return None

        if not isinstance(value, str):
            raise (
                GitHubAdvisoryNormalizationError(
                    f"{field_name} must be "
                    "a string"
                )
            )

        normalized = (
            value
            .replace("\u00a0", " ")
            .strip()
        )

        if not normalized:
            return None

        if len(normalized) > max_length:
            raise (
                GitHubAdvisoryNormalizationError(
                    f"{field_name} exceeds "
                    f"{max_length} characters"
                )
            )

        return (
            transform(normalized)
            if transform
            else normalized
        )

    @staticmethod
    def _clean_string(
        value: Any,
        *,
        max_length: int | None = None,
    ) -> str | None:
        if not isinstance(value, str):
            return None

        normalized = (
            value
            .replace("\u00a0", " ")
            .strip()
        )

        if not normalized:
            return None

        if (
            max_length is not None
            and len(normalized) > max_length
        ):
            return None

        return normalized

    @staticmethod
    def _bounded_float(
        value: Any,
        *,
        minimum: float,
        maximum: float,
    ) -> float | None:
        if (
            value is None
            or isinstance(value, bool)
        ):
            return None

        try:
            parsed = float(value)

        except (TypeError, ValueError):
            return None

        if not (
            minimum
            <= parsed
            <= maximum
        ):
            return None

        return parsed

    @classmethod
    def _extract_string_list(
        cls,
        value: Any,
        *,
        field_name: str,
        max_count: int,
        max_length: int,
    ) -> tuple[str, ...]:
        if value is None:
            return ()

        cls._require_bounded_list(
            value,
            field_name=field_name,
            max_count=max_count,
        )

        result: list[str] = []
        seen: set[str] = set()

        for item in value:
            normalized = cls._clean_string(
                item,
                max_length=max_length,
            )

            if (
                normalized is not None
                and normalized not in seen
            ):
                seen.add(normalized)
                result.append(normalized)

        return tuple(result)

    @staticmethod
    def _require_bounded_list(
        value: Any,
        *,
        field_name: str,
        max_count: int,
    ) -> None:
        if not isinstance(value, list):
            raise (
                GitHubAdvisoryNormalizationError(
                    f"{field_name} must be "
                    "a list"
                )
            )

        if len(value) > max_count:
            raise (
                GitHubAdvisoryNormalizationError(
                    f"{field_name} contains "
                    "too many values"
                )
            )

    @classmethod
    def _normalize_url(
        cls,
        value: Any,
    ) -> str | None:
        normalized = cls._clean_string(
            value,
            max_length=2_048,
        )

        if normalized is None:
            return None

        parsed = urlsplit(normalized)

        if (
            parsed.scheme.lower()
            not in {"http", "https"}
            or not parsed.netloc
            or parsed.username is not None
            or parsed.password is not None
        ):
            return None

        return normalized