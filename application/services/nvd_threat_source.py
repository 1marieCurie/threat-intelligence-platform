# application/services/nvd_threat_source.py

from datetime import UTC, datetime, timedelta
from typing import Any, List
from urllib.parse import unquote

from application.ports.inbound.threat_source import ThreatSource
from domain.collection_result import CollectionResult
from domain.threat import Threat
from domain.weakness_reference import WeaknessReference
from infrastructure.adapters.outbound.nvd_connector import NVDConnector


class NVDThreatSource(ThreatSource):
    """
    Application service responsible for NVD ingestion.

    Responsibilities:
    - fetch raw CVE data through the NVD connector;
    - parse NVD CVE records;
    - normalize CVSS information;
    - normalize affected products;
    - preserve CWE assertions as WeaknessReference objects;
    - return domain Threat objects.
    """

    CVSS_PRIORITY = (
        "cvssMetricV40",
        "cvssMetricV31",
        "cvssMetricV30",
        "cvssMetricV2",
    )

    CWE_PLACEHOLDERS = {
        "NVD-CWE-NOINFO",
        "NVD-CWE-OTHER",
        "CWE-NOINFO",
        "CWE-OTHER",
    }

    def __init__(self) -> None:
        self.connector = NVDConnector()

    def name(self) -> str:
        return "NVD"

    def collect(self) -> CollectionResult:
        """
        Fetch and parse NVD CVEs into a CollectionResult.
        """

        raw = self.fetch_raw()
        threats = self.parse(raw)

        metadata = {
            "source": self.name(),
            "total_results": raw.get("totalResults"),
            "results_per_page": raw.get(
                "resultsPerPage"
            ),
            "start_index": raw.get("startIndex"),
            "version": raw.get("version"),
            "timestamp": raw.get("timestamp"),
        }

        return CollectionResult(
            threats=threats,
            metadata=metadata,
        )

    def fetch_raw(self) -> Any:
        """
        Fetch NVD CVEs published during the last seven days.
        """

        end_date = datetime.now(UTC)
        start_date = end_date - timedelta(days=7)

        return self.connector.fetch(
            start_date=start_date.strftime(
                "%Y-%m-%dT%H:%M:%S.000Z"
            ),
            end_date=end_date.strftime(
                "%Y-%m-%dT%H:%M:%S.000Z"
            ),
            results_per_page=100,
            start_index=0,
        )

    def parse(
    self,
    raw_data: Any,
) -> List[Threat]:
        """
        Parse the NVD API response into Threat objects.

        Invalid top-level values and malformed vulnerability elements
        are ignored safely.
        """

        if not isinstance(raw_data, dict):
            return []

        vulnerabilities = raw_data.get(
            "vulnerabilities",
            [],
        )

        if not isinstance(vulnerabilities, list):
            return []

        threats: List[Threat] = []

        for item in vulnerabilities:
            if not isinstance(item, dict):
                continue

            cve = item.get("cve")

            if not isinstance(cve, dict):
                continue

            threats.append(
                self._parse_cve(cve)
            )

        return threats

    def _parse_cve(
        self,
        cve: dict[str, Any],
    ) -> Threat:
        """
        Convert one NVD CVE record into a Threat object.
        """

        cve_id = cve.get("id")

        if not isinstance(cve_id, str):
            raise ValueError(
                "Missing CVE identifier."
            )

        cve_id = cve_id.strip()

        if not cve_id:
            raise ValueError(
                "Missing CVE identifier."
            )

        return Threat(
            id=cve_id,
            source=self.name(),
            description=self._extract_description(
                cve
            ),
            severity=self._extract_severity(cve),
            cvss_score=self._extract_cvss(cve),
            affected_products=(
                self._extract_affected_products(cve)
            ),
            weakness_references=(
                self._extract_weakness_references(cve)
            ),
            references=self._extract_references(
                cve
            ),
            published_date=cve.get("published"),
            last_modified_date=cve.get(
                "lastModified"
            ),
            raw=cve,
        )

    # =========================================================
    # Description
    # =========================================================

    def _extract_description(
        self,
        cve: dict[str, Any],
    ) -> str:
        """
        Return the English description when available.

        If no English description exists, return the first valid
        description found.
        """

        descriptions = cve.get(
            "descriptions",
            [],
        )

        if not isinstance(descriptions, list):
            return ""

        fallback_description = ""

        for description in descriptions:
            if not isinstance(description, dict):
                continue

            value = description.get("value")

            if not isinstance(value, str):
                continue

            value = self._clean_text(value)

            if not fallback_description:
                fallback_description = value

            if description.get("lang") == "en":
                return value

        return fallback_description

    @staticmethod
    def _clean_text(value: str) -> str:
        """
        Normalize special spaces and surrounding whitespace.
        """

        return (
            value
            .replace("\u00a0", " ")
            .strip()
        )

    # =========================================================
    # CVSS
    # =========================================================

    def _extract_severity(
        self,
        cve: dict[str, Any],
    ) -> str | None:
        """
        Extract severity from the highest-priority CVSS metric.

        CVSS v3.x and v4.0 store baseSeverity inside cvssData.
        CVSS v2 usually stores baseSeverity at metric level.
        """

        metric = self._extract_cvss_metric(cve)

        if not metric:
            return None

        cvss_data = metric.get(
            "cvssData",
            {},
        )

        if isinstance(cvss_data, dict):
            severity = cvss_data.get(
                "baseSeverity"
            )

            if isinstance(severity, str):
                return severity

        legacy_severity = metric.get(
            "baseSeverity"
        )

        if isinstance(legacy_severity, str):
            return legacy_severity

        return None

    def _extract_cvss(
        self,
        cve: dict[str, Any],
    ) -> float | None:
        """
        Extract the base score from the highest-priority
        available CVSS metric.
        """

        metric = self._extract_cvss_metric(cve)

        if not metric:
            return None

        cvss_data = metric.get(
            "cvssData",
            {},
        )

        if not isinstance(cvss_data, dict):
            return None

        base_score = cvss_data.get(
            "baseScore"
        )

        if isinstance(base_score, bool):
            return None

        if isinstance(base_score, (int, float)):
            return float(base_score)

        return None

    def _extract_cvss_metric(
        self,
        cve: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Return the highest-priority valid CVSS metric.

        Priority:
        1. CVSS v4.0
        2. CVSS v3.1
        3. CVSS v3.0
        4. CVSS v2.0
        """

        metrics = cve.get("metrics", {})

        if not isinstance(metrics, dict):
            return {}

        for version in self.CVSS_PRIORITY:
            version_metrics = metrics.get(version)

            if not isinstance(
                version_metrics,
                list,
            ):
                continue

            for metric in version_metrics:
                if isinstance(metric, dict):
                    return metric

        return {}

    # =========================================================
    # Affected products
    # =========================================================

    def _extract_affected_products(
        self,
        cve: dict[str, Any],
    ) -> List[dict[str, Any]]:
        """
        Extract affected products from NVD configurations.

        NVD represents affected products through CPE matches inside:

            configurations
                -> nodes
                    -> cpeMatch

        Nested child nodes are supported recursively.

        A legacy fallback for an ``affected`` field is retained so
        older fixtures remain compatible.
        """

        products = self._extract_products_from_configurations(
            cve
        )

        if products:
            return products

        return self._extract_legacy_affected_products(
            cve
        )

    def _extract_products_from_configurations(
        self,
        cve: dict[str, Any],
    ) -> List[dict[str, Any]]:
        """
        Extract and deduplicate products from NVD CPE matches.
        """

        configurations = cve.get(
            "configurations",
            [],
        )

        if not isinstance(configurations, list):
            return []

        products: List[dict[str, Any]] = []
        seen: set[tuple[Any, ...]] = set()

        for configuration in configurations:
            if not isinstance(
                configuration,
                dict,
            ):
                continue

            nodes = configuration.get(
                "nodes",
                [],
            )

            if not isinstance(nodes, list):
                continue

            for node in nodes:
                self._collect_products_from_node(
                    node=node,
                    products=products,
                    seen=seen,
                )

        return products

    def _collect_products_from_node(
        self,
        node: Any,
        products: List[dict[str, Any]],
        seen: set[tuple[Any, ...]],
    ) -> None:
        """
        Recursively traverse an NVD configuration node.
        """

        if not isinstance(node, dict):
            return

        cpe_matches = node.get(
            "cpeMatch",
            [],
        )

        if isinstance(cpe_matches, list):
            for cpe_match in cpe_matches:
                product = self._parse_cpe_match(
                    cpe_match
                )

                if product is None:
                    continue

                key = self._affected_product_key(
                    product
                )

                if key in seen:
                    continue

                seen.add(key)
                products.append(product)

        child_nodes = node.get(
            "children",
            [],
        )

        if isinstance(child_nodes, list):
            for child_node in child_nodes:
                self._collect_products_from_node(
                    node=child_node,
                    products=products,
                    seen=seen,
                )

        nested_nodes = node.get(
            "nodes",
            [],
        )

        if isinstance(nested_nodes, list):
            for nested_node in nested_nodes:
                self._collect_products_from_node(
                    node=nested_node,
                    products=products,
                    seen=seen,
                )

    def _parse_cpe_match(
        self,
        cpe_match: Any,
    ) -> dict[str, Any] | None:
        """
        Convert one NVD cpeMatch entry into an affected-product
        representation.

        Example criteria:

            cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*
        """

        if not isinstance(cpe_match, dict):
            return None

        criteria = cpe_match.get("criteria")

        if not isinstance(criteria, str):
            return None

        parsed_cpe = self._parse_cpe_23(criteria)

        versions = self._extract_version_constraints(
            cpe_match=cpe_match,
            cpe_version=parsed_cpe.get(
                "version"
            ),
        )

        return {
            "vendor": parsed_cpe.get("vendor"),
            "product": parsed_cpe.get("product"),
            "part": parsed_cpe.get("part"),
            "platforms": self._extract_cpe_platforms(
                parsed_cpe
            ),
            "versions": versions,
            "vulnerable": cpe_match.get(
                "vulnerable"
            ),
            "criteria": criteria,
            "match_criteria_id": cpe_match.get(
                "matchCriteriaId"
            ),
        }

    @staticmethod
    def _parse_cpe_23(
        criteria: str,
    ) -> dict[str, str | None]:
        """
        Parse the principal components of a CPE 2.3 URI.

        This parser extracts only the fields needed by the domain:
        part, vendor, product, version, target software and
        target hardware.
        """

        parts = criteria.split(":")

        if (
            len(parts) < 6
            or parts[0] != "cpe"
            or parts[1] != "2.3"
        ):
            return {
                "part": None,
                "vendor": None,
                "product": None,
                "version": None,
                "target_sw": None,
                "target_hw": None,
            }

        return {
            "part": NVDThreatSource._normalize_cpe_value(
                parts[2]
            ),
            "vendor": NVDThreatSource._normalize_cpe_value(
                parts[3]
            ),
            "product": NVDThreatSource._normalize_cpe_value(
                parts[4]
            ),
            "version": NVDThreatSource._normalize_cpe_value(
                parts[5]
            ),
            "target_sw": (
                NVDThreatSource._normalize_cpe_value(
                    parts[10]
                )
                if len(parts) > 10
                else None
            ),
            "target_hw": (
                NVDThreatSource._normalize_cpe_value(
                    parts[11]
                )
                if len(parts) > 11
                else None
            ),
        }

    @staticmethod
    def _normalize_cpe_value(
        value: str,
    ) -> str | None:
        """
        Normalize one CPE component.

        CPE wildcards and unavailable values are converted to None.
        """

        if value in {"", "*", "-", "n/a"}:
            return None

        return unquote(
            value.replace("\\", "")
        )

    @staticmethod
    def _extract_cpe_platforms(
        parsed_cpe: dict[str, str | None],
    ) -> List[str]:
        """
        Build a platform list from CPE target software and hardware.
        """

        platforms: List[str] = []

        for field in ("target_sw", "target_hw"):
            value = parsed_cpe.get(field)

            if value and value not in platforms:
                platforms.append(value)

        return platforms

    @staticmethod
    def _extract_version_constraints(
        cpe_match: dict[str, Any],
        cpe_version: str | None,
    ) -> List[dict[str, Any]]:
        """
        Normalize CPE version and version-range constraints.
        """

        version_data: dict[str, Any] = {}

        if cpe_version is not None:
            version_data["version"] = cpe_version

        constraint_fields = (
            "versionStartIncluding",
            "versionStartExcluding",
            "versionEndIncluding",
            "versionEndExcluding",
        )

        for field in constraint_fields:
            value = cpe_match.get(field)

            if value is not None:
                version_data[field] = value

        if not version_data:
            return []

        return [version_data]

    @staticmethod
    def _affected_product_key(
        product: dict[str, Any],
    ) -> tuple[Any, ...]:
        """
        Build a stable deduplication key for an affected product.
        """

        versions = product.get("versions", [])

        normalized_versions = tuple(
            tuple(
                sorted(version.items())
            )
            for version in versions
            if isinstance(version, dict)
        )

        platforms = product.get(
            "platforms",
            [],
        )

        normalized_platforms = tuple(
            platforms
            if isinstance(platforms, list)
            else []
        )

        return (
            product.get("vendor"),
            product.get("product"),
            product.get("part"),
            normalized_platforms,
            normalized_versions,
            product.get("criteria"),
        )

    def _extract_legacy_affected_products(
        self,
        cve: dict[str, Any],
    ) -> List[dict[str, Any]]:
        """
        Compatibility fallback for older fixtures containing an
        ``affected`` structure instead of NVD configurations.
        """

        affected_entries = cve.get(
            "affected",
            [],
        )

        if not isinstance(affected_entries, list):
            return []

        products: List[dict[str, Any]] = []

        for affected in affected_entries:
            if not isinstance(affected, dict):
                continue

            affected_data = affected.get(
                "affectedData",
                [],
            )

            if not isinstance(affected_data, list):
                continue

            for item in affected_data:
                if not isinstance(item, dict):
                    continue

                vendor = item.get("vendor")
                product = item.get("product")

                if vendor == "n/a":
                    vendor = None

                if product == "n/a":
                    product = None

                platforms = item.get(
                    "platforms",
                    [],
                )

                if not isinstance(platforms, list):
                    platforms = []

                versions = item.get(
                    "versions",
                    [],
                )

                if not isinstance(versions, list):
                    versions = []

                products.append(
                    {
                        "vendor": vendor,
                        "product": product,
                        "platforms": platforms,
                        "versions": versions,
                    }
                )

        return products

    # =========================================================
    # Weakness references
    # =========================================================

    def _extract_weakness_references(
        self,
        cve: dict[str, Any],
    ) -> List[WeaknessReference]:
        """
        Convert NVD weakness assertions into WeaknessReference
        objects.

        Supported cases:
        - valid CWE IDs: resolved;
        - NVD-CWE-noinfo / NVD-CWE-Other: placeholder;
        - textual descriptions without IDs: unresolved;
        - malformed CWE-like identifiers: invalid.

        Duplicates are removed while preserving order.
        """

        weaknesses = cve.get(
            "weaknesses",
            [],
        )

        if not isinstance(weaknesses, list):
            return []

        references: List[WeaknessReference] = []
        seen: set[
            tuple[
                str | None,
                str | None,
                str,
            ]
        ] = set()

        for weakness in weaknesses:
            if not isinstance(weakness, dict):
                continue

            descriptions = weakness.get(
                "description",
                [],
            )

            if not isinstance(descriptions, list):
                continue

            weakness_type = weakness.get("type")
            origin = self._weakness_origin(
                weakness_type
            )

            for description in descriptions:
                if not isinstance(description, dict):
                    continue

                raw_value = description.get("value")

                if not isinstance(raw_value, str):
                    continue

                source_description = (
                    self._clean_text(raw_value)
                )

                if not source_description:
                    continue

                (
                    cwe_id,
                    resolution_status,
                    resolution_method,
                ) = self._resolve_cwe_value(
                    source_description
                )

                key = (
                    cwe_id,
                    source_description,
                    resolution_status,
                )

                if key in seen:
                    continue

                references.append(
                    WeaknessReference(
                        source=self.name(),
                        cwe_id=cwe_id,
                        source_description=(
                            source_description
                        ),
                        source_type=(
                            weakness_type
                            if isinstance(
                                weakness_type,
                                str,
                            )
                            else None
                        ),
                        language=description.get(
                            "lang"
                        ),
                        origin=origin,
                        resolution_status=(
                            resolution_status
                        ),
                        resolution_method=(
                            resolution_method
                        ),
                        raw={
                            "weakness_source": (
                                weakness.get("source")
                            ),
                            "weakness_type": (
                                weakness_type
                            ),
                            "description": description,
                        },
                    )
                )

                seen.add(key)

        return references

    def _resolve_cwe_value(
        self,
        value: str,
    ) -> tuple[
        str | None,
        str,
        str | None,
    ]:
        """
        Resolve one NVD weakness description.

        Returns:
            (
                canonical_cwe_id,
                resolution_status,
                resolution_method,
            )
        """

        normalized = value.strip().upper()

        if normalized in self.CWE_PLACEHOLDERS:
            return (
                None,
                "placeholder",
                "source_placeholder",
            )

        canonical_id = self._normalize_cwe_id(
            normalized
        )

        if canonical_id is not None:
            return (
                canonical_id,
                "resolved",
                "explicit_id",
            )

        extracted_id = self._extract_cwe_id_from_text(
            normalized
        )

        if extracted_id is not None:
            return (
                extracted_id,
                "resolved",
                "extracted_id",
            )

        if normalized.startswith("CWE-"):
            return (
                None,
                "invalid",
                None,
            )

        return (
            None,
            "unresolved",
            None,
        )

    @staticmethod
    def _normalize_cwe_id(
        value: Any,
    ) -> str | None:
        """
        Normalize a dedicated CWE value to CWE-N.

        Accepted examples:
            CWE-79
            cwe-79
            79
            "79"
        """

        if isinstance(value, bool):
            return None

        if isinstance(value, int):
            if value <= 0:
                return None

            return f"CWE-{value}"

        if not isinstance(value, str):
            return None

        normalized = value.strip().upper()

        if not normalized:
            return None

        if normalized.isdigit():
            number = int(normalized)

            if number <= 0:
                return None

            return f"CWE-{number}"

        if normalized.startswith("CWE-"):
            number = normalized.removeprefix(
                "CWE-"
            )

            if number.isdigit():
                number_value = int(number)

                if number_value > 0:
                    return f"CWE-{number_value}"

        return None

    @staticmethod
    def _extract_cwe_id_from_text(
        value: str,
    ) -> str | None:
        """
        Extract a CWE identifier from combined text.

        Example:
            "CWE-79: Improper Neutralization of Input"
        """

        for token in value.replace(
            ":",
            " ",
        ).replace(
            ",",
            " ",
        ).replace(
            "(",
            " ",
        ).replace(
            ")",
            " ",
        ).split():
            normalized = (
                NVDThreatSource._normalize_cwe_id(
                    token
                )
            )

            if normalized is not None:
                return normalized

        return None

    @staticmethod
    def _weakness_origin(
        weakness_type: Any,
    ) -> str:
        """
        Convert the NVD weakness classification into an origin.
        """

        if not isinstance(weakness_type, str):
            return "nvd"

        normalized = weakness_type.strip().lower()

        if normalized == "primary":
            return "nvd_primary"

        if normalized == "secondary":
            return "nvd_secondary"

        return "nvd"

    # =========================================================
    # References
    # =========================================================

    def _extract_references(
        self,
        cve: dict[str, Any],
    ) -> List[str]:
        """
        Extract valid reference URLs and remove duplicates while
        preserving their original order.
        """

        raw_references = cve.get(
            "references",
            [],
        )

        if not isinstance(raw_references, list):
            return []

        references: List[str] = []
        seen: set[str] = set()

        for reference in raw_references:
            if not isinstance(reference, dict):
                continue

            url = reference.get("url")

            if not isinstance(url, str):
                continue

            url = url.strip()

            if not url or url in seen:
                continue

            references.append(url)
            seen.add(url)

        return references