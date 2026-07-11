from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from application.ports.inbound.threat_source import ThreatSource
from domain.collection_result import CollectionResult
from domain.threat import Threat
from infrastructure.adapters.outbound.github_advisory_connector import (
    GitHubAdvisoryConnector,
)


class GitHubAdvisoryThreatSource(ThreatSource):
    """
    Application service responsible for collecting GitHub Security
    Advisories and mapping them to normalized Threat entities.

    The outbound connector retrieves raw GitHub dictionaries.
    This service contains the GitHub-specific normalization rules.
    """

    SOURCE_NAME = "github_advisory"

    def __init__(
        self,
        connector: GitHubAdvisoryConnector | None = None,
        *,
        advisory_type: str = "reviewed",
        ecosystem: str | None = None,
        severity: str | None = None,
        modified: str | None = None,
        per_page: int = 100,
        max_pages: int | None = 1,
    ) -> None:
        self.connector = connector or GitHubAdvisoryConnector()

        self.advisory_type = advisory_type
        self.ecosystem = ecosystem
        self.severity = severity
        self.modified = modified
        self.per_page = per_page
        self.max_pages = max_pages

    def name(self) -> str:
        """
        Return the normalized source name.
        """

        return self.SOURCE_NAME

    def collect(self) -> CollectionResult:
        """
        Collect raw GitHub advisories and map them to Threat entities.
        """

        raw_advisories = self.fetch_raw()
        threats = self.parse(raw_advisories)

        metadata: dict[str, Any] = {
            "source": self.SOURCE_NAME,
            "api_version": self.connector.API_VERSION,
            "advisory_type": self.advisory_type,
            "ecosystem": self.ecosystem,
            "severity": self.severity,
            "modified": self.modified,
            "per_page": self.per_page,
            "max_pages": self.max_pages,
            "collected_count": len(raw_advisories),
            "parsed_count": len(threats),
            "skipped_count": len(raw_advisories) - len(threats),
            "collected_at": datetime.now(
                timezone.utc
            ).isoformat(),
        }

        return CollectionResult(
            threats=threats,
            metadata=metadata,
        )

    def fetch_raw(self) -> list[dict[str, Any]]:
        """
        Retrieve raw advisories through the outbound connector.
        """

        return self.connector.fetch_advisories(
            advisory_type=self.advisory_type,
            ecosystem=self.ecosystem,
            severity=self.severity,
            modified=self.modified,
            per_page=self.per_page,
            max_pages=self.max_pages,
        )

    def parse(
        self,
        raw_data: Any,
    ) -> list[Threat]:
        """
        Convert raw GitHub advisory dictionaries into Threat entities.

        Invalid elements that are not dictionaries are ignored.
        Advisories without any usable CVE or GHSA identifier are ignored.
        """

        if not isinstance(raw_data, list):
            raise ValueError(
                "GitHub Advisory raw data must be a list."
            )

        threats: list[Threat] = []

        for advisory in raw_data:
            if not isinstance(advisory, dict):
                continue

            threat = self._map_advisory(advisory)

            if threat is not None:
                threats.append(threat)

        return threats

    def _map_advisory(
        self,
        advisory: dict[str, Any],
    ) -> Threat | None:
        """
        Map one GitHub advisory to one normalized Threat.
        """

        ghsa_id = self._clean_string(
            advisory.get("ghsa_id")
        )

        cve_id = self._clean_string(
            advisory.get("cve_id")
        )

        external_ids = self._extract_external_ids(
            advisory=advisory,
            ghsa_id=ghsa_id,
            cve_id=cve_id,
        )

        canonical_id = self._choose_canonical_id(
            cve_id=cve_id,
            ghsa_id=ghsa_id,
            external_ids=external_ids,
        )

        if canonical_id is None:
            return None

        cvss_metrics = self._extract_cvss_metrics(
            advisory
        )

        cvss_score = self._select_primary_cvss_score(
            cvss_metrics
        )

        epss_score, epss_percentile = (
            self._extract_epss(advisory)
        )

        affected_products = self._extract_affected_products(
            advisory
        )

        weaknesses = self._extract_weaknesses(
            advisory
        )

        weakness_details = self._extract_weakness_details(
            advisory
        )

        references = self._extract_references(
            advisory
        )

        source_urls = self._extract_source_urls(
            advisory
        )

        source_dates = self._extract_source_dates(
            advisory
        )

        source_code_locations = (
            self._extract_source_code_locations(
                advisory
            )
        )

        severity = self._normalize_severity(
            advisory.get("severity")
        )

        labels = self._build_labels(
            advisory=advisory,
            affected_products=affected_products,
        )

        return Threat(
            id=canonical_id,
            external_ids=external_ids,
            title=self._clean_string(
                advisory.get("summary")
            ),
            description=(
                self._clean_string(
                    advisory.get("description")
                )
                or ""
            ),
            advisory_type=self._clean_string(
                advisory.get("type")
            ),
            severity=severity,
            cvss_score=cvss_score,
            cvss_metrics=cvss_metrics,
            epss_score=epss_score,
            epss_percentile=epss_percentile,
            epss_date=None,
            affected_products=affected_products,
            weaknesses=weaknesses,
            weakness_details=weakness_details,
            labels=labels,
            references=references,
            source_urls=source_urls,
            source_code_locations=source_code_locations,
            published_date=self._clean_string(
                advisory.get("published_at")
            ),
            last_modified_date=self._clean_string(
                advisory.get("updated_at")
            ),
            reviewed_date=self._clean_string(
                advisory.get("github_reviewed_at")
            ),
            withdrawn_date=self._clean_string(
                advisory.get("withdrawn_at")
            ),
            source_dates=source_dates,
            raw={
                self.SOURCE_NAME: advisory,
            },
        )

    # ============================================================
    # Identity
    # ============================================================

    @staticmethod
    def _choose_canonical_id(
        *,
        cve_id: str | None,
        ghsa_id: str | None,
        external_ids: dict[str, list[str]],
    ) -> str | None:
        """
        Select the canonical Threat identifier.

        Priority:
        1. Direct CVE identifier
        2. CVE identifier from identifiers[]
        3. Direct GHSA identifier
        4. GHSA identifier from identifiers[]
        """

        if cve_id:
            return cve_id

        cve_identifiers = external_ids.get(
            "CVE",
            [],
        )

        if cve_identifiers:
            return cve_identifiers[0]

        if ghsa_id:
            return ghsa_id

        ghsa_identifiers = external_ids.get(
            "GHSA",
            [],
        )

        if ghsa_identifiers:
            return ghsa_identifiers[0]

        return None

    @classmethod
    def _extract_external_ids(
        cls,
        *,
        advisory: dict[str, Any],
        ghsa_id: str | None,
        cve_id: str | None,
    ) -> dict[str, list[str]]:
        """
        Normalize all identifiers associated with an advisory.

        Example:

        {
            "CVE": ["CVE-2021-44228"],
            "GHSA": ["GHSA-jfh8-c2jp-5v3q"],
        }
        """

        external_ids: dict[str, list[str]] = {}

        identifiers = advisory.get("identifiers")

        if isinstance(identifiers, list):
            for identifier in identifiers:
                if not isinstance(identifier, dict):
                    continue

                identifier_type = cls._clean_string(
                    identifier.get("type")
                )

                identifier_value = cls._clean_string(
                    identifier.get("value")
                )

                if not identifier_type or not identifier_value:
                    continue

                cls._append_unique_identifier(
                    external_ids=external_ids,
                    identifier_type=identifier_type.upper(),
                    identifier_value=identifier_value,
                )

        if cve_id:
            cls._append_unique_identifier(
                external_ids=external_ids,
                identifier_type="CVE",
                identifier_value=cve_id,
            )

        if ghsa_id:
            cls._append_unique_identifier(
                external_ids=external_ids,
                identifier_type="GHSA",
                identifier_value=ghsa_id,
            )

        return external_ids

    @staticmethod
    def _append_unique_identifier(
        *,
        external_ids: dict[str, list[str]],
        identifier_type: str,
        identifier_value: str,
    ) -> None:
        values = external_ids.setdefault(
            identifier_type,
            [],
        )

        if identifier_value not in values:
            values.append(identifier_value)

    # ============================================================
    # CVSS
    # ============================================================

    @classmethod
    def _extract_cvss_metrics(
        cls,
        advisory: dict[str, Any],
    ) -> dict[str, dict[str, Any]]:
        """
        Preserve all CVSS versions supplied by GitHub.

        Expected structure:

        cvss_severities:
            cvss_v3:
                score
                vector_string
            cvss_v4:
                score
                vector_string
        """

        metrics: dict[str, dict[str, Any]] = {}

        cvss_severities = advisory.get(
            "cvss_severities"
        )

        if isinstance(cvss_severities, dict):
            cls._add_cvss_metric(
                metrics=metrics,
                fallback_version="3",
                data=cvss_severities.get("cvss_v3"),
            )

            cls._add_cvss_metric(
                metrics=metrics,
                fallback_version="4",
                data=cvss_severities.get("cvss_v4"),
            )

        # Compatibility with older GitHub responses or fixtures
        # containing only a top-level "cvss" object.
        legacy_cvss = advisory.get("cvss")

        has_cvss_v3 = any(
            version.startswith("3")
            for version in metrics
        )

        if (
            isinstance(legacy_cvss, dict)
            and not has_cvss_v3
        ):
            score = cls._to_float(
                legacy_cvss.get("score")
            )

            vector = cls._clean_string(
                legacy_cvss.get("vector_string")
            )

            version = (
                cls._extract_cvss_version(vector)
                or "3"
            )

            if score is not None or vector is not None:
                metrics[version] = {
                    "score": score,
                    "vector": vector,
                }

        return metrics

    @classmethod
    def _add_cvss_metric(
        cls,
        *,
        metrics: dict[str, dict[str, Any]],
        fallback_version: str,
        data: Any,
    ) -> None:
        if not isinstance(data, dict):
            return

        score = cls._to_float(
            data.get("score")
        )

        vector = cls._clean_string(
            data.get("vector_string")
        )

        if score is None and vector is None:
            return

        version = (
            cls._extract_cvss_version(vector)
            or fallback_version
        )

        metrics[version] = {
            "score": score,
            "vector": vector,
        }

    @staticmethod
    def _extract_cvss_version(
        vector: str | None,
    ) -> str | None:
        """
        Extract the version from a CVSS vector.

        Examples:
            CVSS:3.1/... -> 3.1
            CVSS:4.0/... -> 4.0
        """

        if not vector:
            return None

        if not vector.upper().startswith("CVSS:"):
            return None

        version_section = vector.split(
            "/",
            1,
        )[0]

        _, _, version = version_section.partition(
            ":"
        )

        return version or None

    @classmethod
    def _select_primary_cvss_score(
        cls,
        metrics: dict[str, dict[str, Any]],
    ) -> float | None:
        """
        Select the main normalized CVSS score.

        Priority:
        1. CVSS 4.x
        2. CVSS 3.x
        3. Any remaining available score
        """

        priority: list[str] = []

        priority.extend(
            version
            for version in metrics
            if version.startswith("4")
        )

        priority.extend(
            version
            for version in metrics
            if version.startswith("3")
            and version not in priority
        )

        priority.extend(
            version
            for version in metrics
            if version not in priority
        )

        for version in priority:
            score = cls._to_float(
                metrics[version].get("score")
            )

            if score is not None:
                return score

        return None

    # ============================================================
    # EPSS
    # ============================================================

    @classmethod
    def _extract_epss(
        cls,
        advisory: dict[str, Any],
    ) -> tuple[float | None, float | None]:
        epss = advisory.get("epss")

        if not isinstance(epss, dict):
            return None, None

        return (
            cls._to_float(
                epss.get("percentage")
            ),
            cls._to_float(
                epss.get("percentile")
            ),
        )

    # ============================================================
    # Affected products
    # ============================================================

    @classmethod
    def _extract_affected_products(
        cls,
        advisory: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """
        Normalize GitHub package vulnerability information.
        """

        affected_products: list[dict[str, Any]] = []

        vulnerabilities = advisory.get(
            "vulnerabilities"
        )

        if not isinstance(vulnerabilities, list):
            return affected_products

        for vulnerability in vulnerabilities:
            if not isinstance(vulnerability, dict):
                continue

            package = vulnerability.get("package")

            ecosystem: str | None = None
            package_name: str | None = None

            if isinstance(package, dict):
                ecosystem = cls._clean_string(
                    package.get("ecosystem")
                )

                package_name = cls._clean_string(
                    package.get("name")
                )

            normalized_product: dict[str, Any] = {
                "ecosystem": ecosystem,
                "package_name": package_name,
                "vulnerable_version_range": (
                    cls._clean_string(
                        vulnerability.get(
                            "vulnerable_version_range"
                        )
                    )
                ),
                "first_patched_version": (
                    cls._extract_first_patched_version(
                        vulnerability.get(
                            "first_patched_version"
                        )
                    )
                ),
                "vulnerable_functions": (
                    cls._extract_string_list(
                        vulnerability.get(
                            "vulnerable_functions"
                        )
                    )
                ),
            }

            source_code_location = vulnerability.get(
                "source_code_location"
            )

            if source_code_location is not None:
                normalized_product[
                    "source_code_location"
                ] = source_code_location

            normalized_product = (
                cls._remove_none_values(
                    normalized_product
                )
            )

            if normalized_product not in affected_products:
                affected_products.append(
                    normalized_product
                )

        return affected_products

    @classmethod
    def _extract_first_patched_version(
        cls,
        value: Any,
    ) -> str | None:
        if isinstance(value, dict):
            return cls._clean_string(
                value.get("identifier")
            )

        return cls._clean_string(value)

    # ============================================================
    # CWE weaknesses
    # ============================================================

    @classmethod
    def _extract_weaknesses(
        cls,
        advisory: dict[str, Any],
    ) -> list[str]:
        """
        Extract normalized CWE identifiers.

        Names and other details are preserved separately in
        weakness_details.
        """

        weaknesses: list[str] = []

        cwes = advisory.get("cwes")

        if not isinstance(cwes, list):
            return weaknesses

        for cwe in cwes:
            raw_cwe_id: Any

            if isinstance(cwe, dict):
                raw_cwe_id = cwe.get("cwe_id")
            else:
                raw_cwe_id = cwe

            cwe_id = cls._normalize_cwe_id(
                raw_cwe_id
            )

            if cwe_id and cwe_id not in weaknesses:
                weaknesses.append(cwe_id)

        return weaknesses

    @classmethod
    def _extract_weakness_details(
        cls,
        advisory: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """
        Preserve CWE details supplied directly by GitHub Advisory.

        These values represent a source assertion. They may later
        be complemented by the official MITRE CWE catalog without
        overwriting GitHub's original information.
        """

        details: list[dict[str, Any]] = []

        cwes = advisory.get("cwes")

        if not isinstance(cwes, list):
            return details

        for cwe in cwes:
            if not isinstance(cwe, dict):
                continue

            cwe_id = cls._normalize_cwe_id(
                cwe.get("cwe_id")
            )

            if not cwe_id:
                continue

            name = cls._clean_string(
                cwe.get("name")
            )

            detail: dict[str, Any] = {
                "cwe_id": cwe_id,
                "source": cls.SOURCE_NAME,
                "is_official": False,
            }

            if name:
                detail["name"] = name

            if detail not in details:
                details.append(detail)

        return details

    @classmethod
    def _normalize_cwe_id(
        cls,
        value: Any,
    ) -> str | None:
        """
        Normalize a CWE identifier to CWE-N.

        Examples:
            79       -> CWE-79
            "79"     -> CWE-79
            "cwe-79" -> CWE-79
            "CWE-79" -> CWE-79
        """

        if isinstance(value, int):
            if value < 0:
                return None

            return f"CWE-{value}"

        normalized = cls._clean_string(value)

        if not normalized:
            return None

        normalized = normalized.upper()

        if normalized.startswith("CWE-"):
            numeric_part = normalized[4:].strip()
        else:
            numeric_part = normalized

        if not numeric_part.isdigit():
            return None

        return f"CWE-{numeric_part}"

    # ============================================================
    # References and URLs
    # ============================================================

    @classmethod
    def _extract_references(
        cls,
        advisory: dict[str, Any],
    ) -> list[str]:
        references = advisory.get("references")

        if not isinstance(references, list):
            return []

        result: list[str] = []

        for reference in references:
            reference_url: str | None = None

            if isinstance(reference, str):
                reference_url = cls._clean_string(
                    reference
                )

            elif isinstance(reference, dict):
                reference_url = cls._clean_string(
                    reference.get("url")
                )

            if (
                reference_url
                and reference_url not in result
            ):
                result.append(reference_url)

        return result

    @classmethod
    def _extract_source_urls(
        cls,
        advisory: dict[str, Any],
    ) -> dict[str, str]:
        candidates = {
            "api": advisory.get("url"),
            "html": advisory.get("html_url"),
            "repository_advisory": advisory.get(
                "repository_advisory_url"
            ),
        }

        result: dict[str, str] = {}

        for key, value in candidates.items():
            normalized_value = cls._clean_string(
                value
            )

            if normalized_value:
                result[key] = normalized_value

        return result

    # ============================================================
    # Dates
    # ============================================================

    @classmethod
    def _extract_source_dates(
        cls,
        advisory: dict[str, Any],
    ) -> dict[str, str]:
        candidates = {
            "github_published_at": advisory.get(
                "published_at"
            ),
            "github_updated_at": advisory.get(
                "updated_at"
            ),
            "github_reviewed_at": advisory.get(
                "github_reviewed_at"
            ),
            "nvd_published_at": advisory.get(
                "nvd_published_at"
            ),
            "withdrawn_at": advisory.get(
                "withdrawn_at"
            ),
        }

        result: dict[str, str] = {}

        for key, value in candidates.items():
            normalized_value = cls._clean_string(
                value
            )

            if normalized_value:
                result[key] = normalized_value

        return result

    # ============================================================
    # Source code locations
    # ============================================================

    @classmethod
    def _extract_source_code_locations(
        cls,
        advisory: dict[str, Any],
    ) -> list[str]:
        locations: list[str] = []

        cls._append_source_location(
            locations=locations,
            value=advisory.get(
                "source_code_location"
            ),
        )

        vulnerabilities = advisory.get(
            "vulnerabilities"
        )

        if isinstance(vulnerabilities, list):
            for vulnerability in vulnerabilities:
                if not isinstance(vulnerability, dict):
                    continue

                cls._append_source_location(
                    locations=locations,
                    value=vulnerability.get(
                        "source_code_location"
                    ),
                )

        return locations

    @classmethod
    def _append_source_location(
        cls,
        *,
        locations: list[str],
        value: Any,
    ) -> None:
        if isinstance(value, str):
            normalized = cls._clean_string(value)

            if (
                normalized
                and normalized not in locations
            ):
                locations.append(normalized)

        elif isinstance(value, list):
            for item in value:
                cls._append_source_location(
                    locations=locations,
                    value=item,
                )

        elif isinstance(value, dict):
            for key in (
                "url",
                "path",
                "location",
            ):
                normalized = cls._clean_string(
                    value.get(key)
                )

                if (
                    normalized
                    and normalized not in locations
                ):
                    locations.append(normalized)

    # ============================================================
    # Labels and normalization helpers
    # ============================================================

    @classmethod
    def _build_labels(
        cls,
        *,
        advisory: dict[str, Any],
        affected_products: list[dict[str, Any]],
    ) -> list[str]:
        labels: list[str] = []

        advisory_type = cls._clean_string(
            advisory.get("type")
        )

        if advisory_type:
            labels.append(
                f"github:{advisory_type.lower()}"
            )

        for product in affected_products:
            ecosystem = cls._clean_string(
                product.get("ecosystem")
            )

            if not ecosystem:
                continue

            ecosystem_label = (
                f"ecosystem:{ecosystem.lower()}"
            )

            if ecosystem_label not in labels:
                labels.append(ecosystem_label)

        return labels

    @staticmethod
    def _normalize_severity(
        value: Any,
    ) -> str | None:
        if not isinstance(value, str):
            return None

        normalized = value.strip().upper()

        return normalized or None

    @staticmethod
    def _clean_string(
        value: Any,
    ) -> str | None:
        if not isinstance(value, str):
            return None

        normalized = value.strip()

        return normalized or None

    @staticmethod
    def _to_float(
        value: Any,
    ) -> float | None:
        if value is None:
            return None

        try:
            return float(value)
        except (TypeError, ValueError):
            return None

    @classmethod
    def _extract_string_list(
        cls,
        value: Any,
    ) -> list[str]:
        if not isinstance(value, list):
            return []

        result: list[str] = []

        for item in value:
            normalized = cls._clean_string(item)

            if normalized and normalized not in result:
                result.append(normalized)

        return result

    @staticmethod
    def _remove_none_values(
        data: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Remove unavailable scalar values while preserving valid
        empty lists such as vulnerable_functions=[].
        """

        return {
            key: value
            for key, value in data.items()
            if value is not None
        }