from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from application.ports.outbound.ingestion_connector import (
    FetchedRecord,
    FetchResult,
)
from infrastructure.adapters.outbound.cisa_connector import (
    CISAConnector,
)


class CisaKevIngestionConnector:
    """
    Adapte le catalogue CISA KEV au contrat générique
    d'ingestion brute.

    Une vulnérabilité CISA devient un FetchedRecord
    identifié par son CVE.
    """

    VERSION = "1.0.0"
    SOURCE_NAME = "cisa_kev"

    def __init__(
        self,
        *,
        connector: CISAConnector,
    ) -> None:
        if connector is None:
            raise ValueError(
                "CISA connector must not be None."
            )

        self._connector = connector

    def fetch(
        self,
        *,
        cursor: str | None,
        state_metadata: dict[str, Any] | None = None,
    ) -> FetchResult:
        if cursor is not None:
            raise ValueError(
                "CISA KEV does not support cursors."
            )

        # CISA KEV est récupéré comme un snapshot complet.
        # Aucun état précédent n'est nécessaire pour cet adaptateur.
        del state_metadata

        catalog = self._connector.fetch()

        if not isinstance(catalog, dict):
            raise ValueError(
                "Invalid CISA KEV response: expected an object."
            )

        vulnerabilities = catalog.get(
            "vulnerabilities"
        )

        if not isinstance(vulnerabilities, list):
            raise ValueError(
                "Invalid CISA KEV response: "
                "vulnerabilities must be a list."
            )

        declared_count = self._extract_declared_count(
            catalog
        )

        if declared_count != len(vulnerabilities):
            raise ValueError(
                "Invalid CISA KEV response: declared count "
                "does not match vulnerabilities length."
            )

        records: list[FetchedRecord] = []
        seen_cve_ids: set[str] = set()
        fetched_at = datetime.now(UTC)

        for vulnerability in vulnerabilities:
            if not isinstance(vulnerability, dict):
                raise ValueError(
                    "Invalid CISA KEV vulnerability: "
                    "expected an object."
                )

            cve_id = self._extract_cve_id(
                vulnerability
            )

            if cve_id in seen_cve_ids:
                raise ValueError(
                    "Invalid CISA KEV response: "
                    f"duplicate CVE identifier {cve_id}."
                )

            records.append(
                FetchedRecord(
                    external_record_id=cve_id,
                    payload=dict(vulnerability),
                    source_url=CISAConnector.KEV_URL,
                    fetched_at=fetched_at,
                    http_status=200,
                )
            )

            seen_cve_ids.add(cve_id)

        metadata = {
            "source": self.SOURCE_NAME,
            "title": self._clean_optional_string(
                catalog.get("title")
            ),
            "catalog_version": (
                self._clean_optional_string(
                    catalog.get("catalogVersion")
                )
            ),
            "date_released": (
                self._clean_optional_string(
                    catalog.get("dateReleased")
                )
            ),
            "declared_count": declared_count,
            "records_count": len(records),
            "pagination_complete": True,
        }

        return FetchResult(
            records=records,
            next_cursor=None,
            metadata=metadata,
            connector_version=self.VERSION,
        )

    @staticmethod
    def _extract_declared_count(
        catalog: dict[str, Any],
    ) -> int:
        value = catalog.get("count")

        if (
            isinstance(value, bool)
            or not isinstance(value, int)
            or value < 0
        ):
            raise ValueError(
                "Invalid CISA KEV response: "
                "count must be a non-negative integer."
            )

        return value

    @staticmethod
    def _extract_cve_id(
        vulnerability: dict[str, Any],
    ) -> str:
        value = vulnerability.get("cveID")

        if not isinstance(value, str):
            raise ValueError(
                "CISA KEV vulnerability is missing cveID."
            )

        normalized = value.strip().upper()

        if not normalized.startswith("CVE-"):
            raise ValueError(
                "CISA KEV vulnerability has an invalid cveID."
            )

        return normalized

    @staticmethod
    def _clean_optional_string(
        value: Any,
    ) -> str | None:
        if not isinstance(value, str):
            return None

        normalized = value.strip()

        return normalized or None