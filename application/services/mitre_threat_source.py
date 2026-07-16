# application/services/mitre_threat_source.py

from __future__ import annotations

from typing import Any

from application.ports.inbound.threat_source import ThreatSource
from domain.collection_result import CollectionResult
from domain.threat import Threat
from domain.threat_category import ThreatCategory
from domain.weakness_reference import WeaknessReference
from infrastructure.adapters.outbound.mitre_connector import (
    MITREConnector,
)
from infrastructure.persistence.mitre_sync_state import (
    MITRESyncState,
)


class MITREThreatSource(ThreatSource):
    """
    Application service responsible for MITRE CVE List ingestion.

    Responsibilities:
    - retrieve newly published or modified CVE records;
    - transform MITRE CVE records into vulnerability Threat entities;
    - normalize CWE assertions into WeaknessReference objects;
    - enrich CNA information with optional ADP containers;
    - persist the MITRE synchronization state.
    """

    SOURCE_NAME = "MITRE"

    THREAT_CATEGORY = (
        ThreatCategory.VULNERABILITY
    )

    CWE_PLACEHOLDERS = {
        "NVD-CWE-NOINFO",
        "NVD-CWE-OTHER",
        "CWE-NOINFO",
        "CWE-OTHER",
    }

    def __init__(
        self,
        connector: MITREConnector | None = None,
        sync_state: MITRESyncState | None = None,
    ) -> None:
        self.connector = connector or MITREConnector()
        self.sync_state = sync_state or MITRESyncState()

    def name(self) -> str:
        """
        Return the normalized source name.
        """

        return self.SOURCE_NAME

    def collect(self) -> CollectionResult:
        """
        Retrieve and parse all MITRE records available since the
        previous synchronization.
        """

        raw = self.fetch_raw()

        records = raw.get(
            "records",
            [],
        )

        threats = self.parse(records)

        metadata = {
            "source": self.name(),
            "category": (
                self.THREAT_CATEGORY.value
            ),
            "previous_commit": raw.get(
                "previous_commit"
            ),
            "current_commit": raw.get(
                "current_commit"
            ),
            "records_collected": len(threats),
        }

        return CollectionResult(
            threats=threats,
            metadata=metadata,
        )

    def fetch_raw(self) -> dict[str, Any]:
        """
        Retrieve all newly published or modified MITRE CVE records
        since the last synchronization.
        """

        previous_commit = (
            self.sync_state.get_last_commit()
        )

        current_commit, records = (
            self.connector.fetch_new_records(
                previous_commit
            )
        )

        self.sync_state.save_last_commit(
            current_commit
        )

        return {
            "previous_commit": previous_commit,
            "current_commit": current_commit,
            "records": records,
        }

    def parse(
        self,
        raw_data: Any,
    ) -> list[Threat]:
        """
        Convert raw MITRE CVE records into Threat entities.

        Invalid top-level values and malformed record elements are
        ignored safely.
        """

        if not isinstance(raw_data, list):
            return []

        threats: list[Threat] = []

        for record in raw_data:
            if not isinstance(record, dict):
                continue

            threats.append(
                self._parse_record(record)
            )

        return threats

    def _parse_record(
        self,
        record: dict[str, Any],
    ) -> Threat:
        """
        Convert one MITRE CVE record into a vulnerability Threat.

        The CNA container supplies the primary vulnerability data.
        Optional ADP containers enrich the resulting Threat.
        """

        metadata = record.get(
            "cveMetadata",
            {},
        )

        if not isinstance(metadata, dict):
            metadata = {}

        containers = record.get(
            "containers",
            {},
        )

        if not isinstance(containers, dict):
            containers = {}

        cna = containers.get(
            "cna",
            {},
        )

        if not isinstance(cna, dict):
            cna = {}

        cve_id = metadata.get(
            "cveId"
        )

        if not isinstance(cve_id, str):
            raise ValueError(
                "Missing CVE identifier."
            )

        cve_id = cve_id.strip()

        if not cve_id:
            raise ValueError(
                "Missing CVE identifier."
            )

        threat = Threat(
            id=cve_id,
            category=self.THREAT_CATEGORY,
            source=self.SOURCE_NAME,
            title=self._extract_title(cna),
            description=(
                self._extract_description(cna)
            ),
            severity=(
                self._extract_severity(cna)
            ),
            cvss_score=(
                self._extract_cvss(cna)
            ),
            affected_products=(
                self._extract_affected_products(
                    cna
                )
            ),
            weakness_references=(
                self._extract_weakness_references(
                    cna,
                    origin="cna",
                )
            ),
            labels=(
                self._extract_labels(cna)
            ),
            references=(
                self._extract_references(cna)
            ),
            remediation=(
                self._extract_remediation(cna)
            ),
            published_date=(
                self._clean_optional_string(
                    metadata.get(
                        "datePublished"
                    )
                )
            ),
            last_modified_date=(
                self._clean_optional_string(
                    metadata.get(
                        "dateUpdated"
                    )
                )
            ),
            source_dates=(
                self._extract_source_dates(
                    metadata
                )
            ),
            raw=record,
        )

        self._merge_adp_enrichments(
            threat=threat,
            record=record,
        )

        return threat

    # =========================================================
    # Basic fields
    # =========================================================

    @staticmethod
    def _extract_title(
        cna: dict[str, Any],
    ) -> str | None:
        """
        Return a clean CNA title when available.
        """

        title = cna.get("title")

        if not isinstance(title, str):
            return None

        title = (
            title
            .replace("\u00a0", " ")
            .strip()
        )

        return title or None

    def _extract_description(
        self,
        cna: dict[str, Any],
    ) -> str:
        """
        Return the English description when available.

        Otherwise, return the first valid description.
        """

        descriptions = cna.get(
            "descriptions",
            [],
        )

        if not isinstance(descriptions, list):
            return ""

        fallback = ""

        for description in descriptions:
            if not isinstance(description, dict):
                continue

            value = description.get(
                "value"
            )

            if not isinstance(value, str):
                continue

            value = self._clean_text(
                value
            )

            if not value:
                continue

            if not fallback:
                fallback = value

            if description.get("lang") == "en":
                return value

        return fallback

    @staticmethod
    def _clean_text(
        value: str,
    ) -> str:
        """
        Normalize non-breaking spaces and surrounding whitespace.
        """

        return (
            value
            .replace("\u00a0", " ")
            .strip()
        )

    @staticmethod
    def _clean_optional_string(
        value: Any,
    ) -> str | None:
        """
        Normalize an optional source string.

        Empty strings and non-string values become None.
        """

        if not isinstance(value, str):
            return None

        normalized = (
            value
            .replace("\u00a0", " ")
            .strip()
        )

        return normalized or None

    def _extract_source_dates(
        self,
        metadata: dict[str, Any],
    ) -> dict[str, str]:
        """
        Preserve MITRE-specific CVE lifecycle dates.
        """

        source_dates: dict[str, str] = {}

        date_reserved = self._clean_optional_string(
            metadata.get(
                "dateReserved"
            )
        )

        date_published = self._clean_optional_string(
            metadata.get(
                "datePublished"
            )
        )

        date_updated = self._clean_optional_string(
            metadata.get(
                "dateUpdated"
            )
        )

        if date_reserved is not None:
            source_dates[
                "date_reserved"
            ] = date_reserved

        if date_published is not None:
            source_dates[
                "date_published"
            ] = date_published

        if date_updated is not None:
            source_dates[
                "date_updated"
            ] = date_updated

        return source_dates

    # =========================================================
    # CVSS
    # =========================================================

    def _extract_cvss(
        self,
        container: dict[str, Any],
    ) -> float | None:
        """
        Return the first valid CVSS base score found in a MITRE
        CNA or ADP metrics collection.
        """

        metrics = container.get(
            "metrics",
            [],
        )

        if not isinstance(metrics, list):
            return None

        for metric in metrics:
            if not isinstance(metric, dict):
                continue

            for value in metric.values():
                if not isinstance(value, dict):
                    continue

                base_score = value.get(
                    "baseScore"
                )

                if isinstance(base_score, bool):
                    continue

                if isinstance(
                    base_score,
                    (int, float),
                ):
                    return float(base_score)

        return None

    def _extract_severity(
        self,
        container: dict[str, Any],
    ) -> str | None:
        """
        Return the first valid CVSS severity found in a MITRE CNA
        or ADP metrics collection.
        """

        metrics = container.get(
            "metrics",
            [],
        )

        if not isinstance(metrics, list):
            return None

        for metric in metrics:
            if not isinstance(metric, dict):
                continue

            for value in metric.values():
                if not isinstance(value, dict):
                    continue

                severity = value.get(
                    "baseSeverity"
                )

                if isinstance(severity, str):
                    severity = severity.strip()

                    if severity:
                        return severity

        return None

    # =========================================================
    # CWE weakness references
    # =========================================================

    def _extract_weakness_references(
        self,
        container: dict[str, Any],
        *,
        origin: str,
    ) -> list[WeaknessReference]:
        """
        Convert MITRE problemTypes into WeaknessReference objects.

        A MITRE problem-type description can contain:
        - a dedicated cweId field;
        - a description equal to a CWE ID;
        - a combined description such as
          ``CWE-79: Improper Neutralization of Input``;
        - only a textual weakness description.
        """

        problem_types = container.get(
            "problemTypes",
            [],
        )

        if not isinstance(problem_types, list):
            return []

        references: list[
            WeaknessReference
        ] = []

        seen: set[
            tuple[
                str | None,
                str | None,
                str,
                str,
            ]
        ] = set()

        for problem in problem_types:
            if not isinstance(problem, dict):
                continue

            descriptions = problem.get(
                "descriptions",
                [],
            )

            if not isinstance(
                descriptions,
                list,
            ):
                continue

            for description in descriptions:
                if not isinstance(
                    description,
                    dict,
                ):
                    continue

                reference = (
                    self._parse_weakness_description(
                        description=description,
                        origin=origin,
                    )
                )

                if reference is None:
                    continue

                key = (
                    reference.cwe_id,
                    reference.source_description,
                    reference.resolution_status,
                    reference.origin or origin,
                )

                if key in seen:
                    continue

                references.append(
                    reference
                )

                seen.add(key)

        return references

    def _parse_weakness_description(
        self,
        *,
        description: dict[str, Any],
        origin: str,
    ) -> WeaknessReference | None:
        """
        Convert one MITRE problem-type description into a
        WeaknessReference.
        """

        raw_cwe_id = description.get(
            "cweId"
        )

        raw_description = description.get(
            "description"
        )

        source_description = (
            self._clean_text(
                raw_description
            )
            if isinstance(
                raw_description,
                str,
            )
            else None
        )

        source_type = description.get(
            "type"
        )

        if not isinstance(
            source_type,
            str,
        ):
            source_type = None

        language = description.get(
            "lang"
        )

        if not isinstance(
            language,
            str,
        ):
            language = None

        if raw_cwe_id is not None:
            normalized_id = (
                self._normalize_cwe_id(
                    raw_cwe_id
                )
            )

            if normalized_id is not None:
                return WeaknessReference(
                    source=self.SOURCE_NAME,
                    cwe_id=normalized_id,
                    source_description=(
                        source_description
                    ),
                    source_type=source_type,
                    language=language,
                    origin=origin,
                    resolution_status="resolved",
                    resolution_method="explicit_id",
                    raw=description,
                )

            if self._is_cwe_placeholder(
                raw_cwe_id
            ):
                return WeaknessReference(
                    source=self.SOURCE_NAME,
                    cwe_id=None,
                    source_description=(
                        source_description
                        or str(raw_cwe_id)
                    ),
                    source_type=source_type,
                    language=language,
                    origin=origin,
                    resolution_status="placeholder",
                    resolution_method=(
                        "source_placeholder"
                    ),
                    raw=description,
                )

            return WeaknessReference(
                source=self.SOURCE_NAME,
                cwe_id=None,
                source_description=(
                    source_description
                    or str(raw_cwe_id)
                ),
                source_type=source_type,
                language=language,
                origin=origin,
                resolution_status="invalid",
                resolution_method=None,
                raw=description,
            )

        if source_description is None:
            return None

        if self._is_cwe_placeholder(
            source_description
        ):
            return WeaknessReference(
                source=self.SOURCE_NAME,
                cwe_id=None,
                source_description=(
                    source_description
                ),
                source_type=source_type,
                language=language,
                origin=origin,
                resolution_status="placeholder",
                resolution_method=(
                    "source_placeholder"
                ),
                raw=description,
            )

        direct_id = self._normalize_cwe_id(
            source_description
        )

        if direct_id is not None:
            return WeaknessReference(
                source=self.SOURCE_NAME,
                cwe_id=direct_id,
                source_description=(
                    source_description
                ),
                source_type=source_type,
                language=language,
                origin=origin,
                resolution_status="resolved",
                resolution_method="explicit_id",
                raw=description,
            )

        extracted_id = (
            self._extract_cwe_id_from_text(
                source_description
            )
        )

        if extracted_id is not None:
            return WeaknessReference(
                source=self.SOURCE_NAME,
                cwe_id=extracted_id,
                source_description=(
                    source_description
                ),
                source_type=source_type,
                language=language,
                origin=origin,
                resolution_status="resolved",
                resolution_method="extracted_id",
                raw=description,
            )

        if source_description.upper().startswith(
            "CWE-"
        ):
            return WeaknessReference(
                source=self.SOURCE_NAME,
                cwe_id=None,
                source_description=(
                    source_description
                ),
                source_type=source_type,
                language=language,
                origin=origin,
                resolution_status="invalid",
                resolution_method=None,
                raw=description,
            )

        return WeaknessReference(
            source=self.SOURCE_NAME,
            cwe_id=None,
            source_description=(
                source_description
            ),
            source_type=source_type,
            language=language,
            origin=origin,
            resolution_status="unresolved",
            resolution_method=None,
            raw=description,
        )

    @staticmethod
    def _normalize_cwe_id(
        value: Any,
    ) -> str | None:
        """
        Normalize a CWE value into the canonical ``CWE-N`` form.

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

        normalized = (
            value
            .strip()
            .upper()
        )

        if not normalized:
            return None

        if normalized.isdigit():
            number = int(normalized)

            if number <= 0:
                return None

            return f"CWE-{number}"

        if normalized.startswith(
            "CWE-"
        ):
            number = normalized.removeprefix(
                "CWE-"
            )

            if number.isdigit():
                number_value = int(
                    number
                )

                if number_value > 0:
                    return (
                        f"CWE-{number_value}"
                    )

        return None

    def _is_cwe_placeholder(
        self,
        value: Any,
    ) -> bool:
        """
        Return True when the source explicitly supplies a CWE
        placeholder instead of a usable identifier.
        """

        if not isinstance(value, str):
            return False

        return (
            value.strip().upper()
            in self.CWE_PLACEHOLDERS
        )

    @staticmethod
    def _extract_cwe_id_from_text(
        value: str,
    ) -> str | None:
        """
        Extract a canonical CWE identifier from combined text.

        Example:
            CWE-79: Improper Neutralization of Input
        """

        normalized_text = (
            value
            .replace(":", " ")
            .replace(",", " ")
            .replace("(", " ")
            .replace(")", " ")
            .replace("[", " ")
            .replace("]", " ")
        )

        for token in normalized_text.split():
            normalized_id = (
                MITREThreatSource
                ._normalize_cwe_id(
                    token
                )
            )

            if normalized_id is not None:
                return normalized_id

        return None

    # =========================================================
    # References and labels
    # =========================================================

    def _extract_references(
        self,
        container: dict[str, Any],
    ) -> list[str]:
        """
        Extract valid and unique URLs while preserving order.
        """

        raw_references = container.get(
            "references",
            [],
        )

        if not isinstance(
            raw_references,
            list,
        ):
            return []

        references: list[str] = []
        seen: set[str] = set()

        for reference in raw_references:
            if not isinstance(
                reference,
                dict,
            ):
                continue

            url = reference.get(
                "url"
            )

            if not isinstance(url, str):
                continue

            url = url.strip()

            if (
                not url
                or url in seen
            ):
                continue

            references.append(url)
            seen.add(url)

        return references

    def _extract_labels(
        self,
        container: dict[str, Any],
    ) -> list[str]:
        """
        Extract valid and unique MITRE tags.
        """

        raw_tags = container.get(
            "tags",
            [],
        )

        if not isinstance(
            raw_tags,
            list,
        ):
            return []

        labels: list[str] = []
        seen: set[str] = set()

        for tag in raw_tags:
            if not isinstance(tag, str):
                continue

            tag = tag.strip()

            if (
                not tag
                or tag in seen
            ):
                continue

            labels.append(tag)
            seen.add(tag)

        return labels

    # =========================================================
    # Affected products
    # =========================================================

    def _extract_affected_products(
        self,
        container: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """
        Extract MITRE CNA or ADP affected-product entries.
        """

        raw_affected = container.get(
            "affected",
            [],
        )

        if not isinstance(
            raw_affected,
            list,
        ):
            return []

        products: list[
            dict[str, Any]
        ] = []

        for affected in raw_affected:
            if not isinstance(
                affected,
                dict,
            ):
                continue

            versions = affected.get(
                "versions",
                [],
            )

            if not isinstance(
                versions,
                list,
            ):
                versions = []

            platforms = affected.get(
                "platforms",
                [],
            )

            if not isinstance(
                platforms,
                list,
            ):
                platforms = []

            cpes = affected.get(
                "cpes",
                [],
            )

            if not isinstance(cpes, list):
                cpes = []

            vendor = self._clean_optional_string(
                affected.get(
                    "vendor"
                )
            )

            product = self._clean_optional_string(
                affected.get(
                    "product"
                )
            )

            products.append(
                {
                    "vendor": vendor,
                    "product": product,
                    "versions": versions,
                    "platforms": platforms,
                    "cpes": cpes,
                }
            )

        return products

    # =========================================================
    # Remediation
    # =========================================================

    def _extract_remediation(
        self,
        container: dict[str, Any],
    ) -> str | None:
        """
        Extract solutions first, then workarounds as fallback.
        """

        solutions = self._extract_text_values(
            container.get(
                "solutions"
            )
        )

        if solutions:
            return "\n".join(
                solutions
            )

        workarounds = self._extract_text_values(
            container.get(
                "workarounds"
            )
        )

        if workarounds:
            return "\n".join(
                workarounds
            )

        return None

    def _extract_text_values(
        self,
        raw_entries: Any,
    ) -> list[str]:
        """
        Extract non-empty ``value`` fields from a MITRE list.
        """

        if not isinstance(
            raw_entries,
            list,
        ):
            return []

        values: list[str] = []

        for entry in raw_entries:
            if not isinstance(
                entry,
                dict,
            ):
                continue

            value = entry.get(
                "value"
            )

            if not isinstance(value, str):
                continue

            value = self._clean_text(
                value
            )

            if value:
                values.append(value)

        return values

    # =========================================================
    # ADP enrichment
    # =========================================================

    def _merge_adp_enrichments(
        self,
        *,
        threat: Threat,
        record: dict[str, Any],
    ) -> None:
        """
        Enrich a Threat with optional MITRE ADP containers.

        ADP data does not modify the Threat category because the
        record still represents the same CVE vulnerability.
        """

        containers = record.get(
            "containers",
            {},
        )

        if not isinstance(
            containers,
            dict,
        ):
            return

        adps = containers.get(
            "adp",
            [],
        )

        if not isinstance(adps, list):
            return

        for adp in adps:
            if not isinstance(adp, dict):
                continue

            self._merge_references(
                threat=threat,
                adp=adp,
            )

            self._merge_labels(
                threat=threat,
                adp=adp,
            )

            self._merge_weakness_references(
                threat=threat,
                adp=adp,
            )

            self._merge_cvss(
                threat=threat,
                adp=adp,
            )

            self._merge_remediation(
                threat=threat,
                adp=adp,
            )

    def _merge_references(
        self,
        *,
        threat: Threat,
        adp: dict[str, Any],
    ) -> None:
        """
        Merge unique ADP references into the Threat.
        """

        references = self._extract_references(
            adp
        )

        for reference in references:
            if reference not in threat.references:
                threat.references.append(
                    reference
                )

    def _merge_labels(
        self,
        *,
        threat: Threat,
        adp: dict[str, Any],
    ) -> None:
        """
        Merge unique ADP labels into the Threat.
        """

        labels = self._extract_labels(
            adp
        )

        for label in labels:
            if label not in threat.labels:
                threat.labels.append(
                    label
                )

    def _merge_weakness_references(
        self,
        *,
        threat: Threat,
        adp: dict[str, Any],
    ) -> None:
        """
        Merge ADP WeaknessReference objects without losing their
        ADP origin or introducing duplicates.
        """

        references = (
            self._extract_weakness_references(
                adp,
                origin="adp",
            )
        )

        existing_keys = {
            (
                reference.cwe_id,
                reference.source_description,
                reference.resolution_status,
                reference.origin,
            )
            for reference
            in threat.weakness_references
        }

        for reference in references:
            key = (
                reference.cwe_id,
                reference.source_description,
                reference.resolution_status,
                reference.origin,
            )

            if key in existing_keys:
                continue

            threat.weakness_references.append(
                reference
            )

            existing_keys.add(key)

    def _merge_cvss(
        self,
        *,
        threat: Threat,
        adp: dict[str, Any],
    ) -> None:
        """
        Use ADP CVSS values only when CNA did not supply them.
        """

        if threat.cvss_score is None:
            threat.cvss_score = (
                self._extract_cvss(adp)
            )

        if threat.severity is None:
            threat.severity = (
                self._extract_severity(adp)
            )

    def _merge_remediation(
        self,
        *,
        threat: Threat,
        adp: dict[str, Any],
    ) -> None:
        """
        Use ADP remediation only when CNA did not supply one.
        """

        if threat.remediation is None:
            threat.remediation = (
                self._extract_remediation(
                    adp
                )
            )