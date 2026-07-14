from __future__ import annotations

from datetime import datetime, timezone
from ipaddress import ip_address
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from application.ports.inbound.threat_source import ThreatSource
from domain.collection_result import CollectionResult
from domain.indicator import Indicator
from domain.threat import Threat
from infrastructure.adapters.outbound.urlhaus_connector import (
    URLhausConnector,
)


class URLhausThreatSource(ThreatSource):
    """
    Application service responsible for collecting and normalizing
    URLhaus malware-distribution intelligence.

    URLhaus reports URLs that directly distribute malware payloads.
    Each valid URLhaus record is normalized into:

    - one Threat of type ``malware_distribution``;
    - one URL Indicator;
    - one host Indicator when the host is valid;
    - optional file-hash Indicators when detailed payload data
      is available.

    The outbound connector remains responsible only for HTTP
    communication and raw response validation.
    """

    SOURCE_NAME = "URLHAUS"
    NORMALIZED_THREAT_TYPE = "malware_distribution"
    DEFAULT_TITLE = "Malware distribution URL"

    def __init__(
        self,
        connector: Optional[URLhausConnector] = None,
        *,
        limit: Optional[int] = None,
        enrich_with_details: bool = False,
        max_detail_requests: Optional[int] = None,
    ) -> None:
        """
        Initialize the URLhaus threat source.

        Args:
            connector:
                URLhaus outbound connector. A default connector is
                created when omitted.

            limit:
                Optional maximum number of recent URL records to
                retrieve. URLhaus accepts values between 1 and 1000.

            enrich_with_details:
                When True, query the detailed URLhaus endpoint for
                collected records. Detailed responses may provide
                payload hashes, file types and malware signatures.

            max_detail_requests:
                Optional safety limit on the number of detailed API
                calls. Only used when enrich_with_details is True.

        Raises:
            ValueError:
                If max_detail_requests is invalid.
        """
        if (
            max_detail_requests is not None
            and (
                isinstance(max_detail_requests, bool)
                or not isinstance(max_detail_requests, int)
                or max_detail_requests <= 0
            )
        ):
            raise ValueError(
                "max_detail_requests must be a positive integer "
                "or None."
            )

        self._connector = connector or URLhausConnector()
        self._limit = limit
        self._enrich_with_details = enrich_with_details
        self._max_detail_requests = max_detail_requests

    @property
    def name(self) -> str:
        """
        Return the normalized source name.
        """
        return self.SOURCE_NAME

    # ============================================================
    # ThreatSource contract
    # ============================================================

    def fetch_raw(self) -> Dict[str, Any]:
        """
        Retrieve recent URLhaus records.

        Returns:
            Raw URLhaus response containing ``query_status`` and
            optionally an ``urls`` list.
        """
        return self._connector.fetch_recent_urls(
            limit=self._limit
        )

    def parse(
        self,
        raw_data: Dict[str, Any],
    ) -> List[Threat]:
        """
        Normalize a raw URLhaus response into domain Threat objects.

        Malformed records are skipped individually so one invalid
        element does not invalidate the entire collection.

        Args:
            raw_data:
                Raw dictionary returned by URLhausConnector.

        Returns:
            List of normalized Threat objects.
        """
        if not isinstance(raw_data, dict):
            return []

        if raw_data.get("query_status") != "ok":
            return []

        raw_urls = raw_data.get("urls")

        if not isinstance(raw_urls, list):
            return []

        threats: List[Threat] = []
        detail_requests = 0

        for raw_entry in raw_urls:
            if not isinstance(raw_entry, dict):
                continue

            entry = raw_entry

            if self._should_fetch_details(detail_requests):
                detailed_entry = self._fetch_details_safely(
                    raw_entry
                )

                if detailed_entry is not None:
                    entry = self._merge_records(
                        summary=raw_entry,
                        details=detailed_entry,
                    )
                    detail_requests += 1

            threat = self._parse_entry(entry)

            if threat is not None:
                threats.append(threat)

        return threats

    def collect(self) -> CollectionResult:
        """
        Collect and normalize URLhaus records.

        Returns:
            CollectionResult containing normalized threats and
            collection-level metadata.
        """
        collected_at = datetime.now(
            timezone.utc
        ).isoformat()

        raw_data = self.fetch_raw()
        threats = self.parse(raw_data)

        raw_urls = raw_data.get("urls", [])

        received_records = (
            len(raw_urls)
            if isinstance(raw_urls, list)
            else 0
        )

        metadata: Dict[str, Any] = {
            "source": self.name,
            "query_status": raw_data.get("query_status"),
            "requested_limit": self._limit,
            "received_records": received_records,
            "parsed_threats": len(threats),
            "skipped_records": max(
                received_records - len(threats),
                0,
            ),
            "details_enrichment_enabled": (
                self._enrich_with_details
            ),
            "max_detail_requests": self._max_detail_requests,
            "collected_at": collected_at,
        }

        return CollectionResult(
            threats=threats,
            metadata=metadata,
        )

    # ============================================================
    # Record normalization
    # ============================================================

    def _parse_entry(
        self,
        entry: Dict[str, Any],
    ) -> Optional[Threat]:
        """
        Convert one URLhaus entry into a Threat.

        The URLhaus identifier and malicious URL are required.
        Other fields are treated as optional.
        """
        urlhaus_id = self._normalize_identifier(
            entry.get("id")
        )
        malicious_url = self._clean_string(
            entry.get("url")
        )

        if urlhaus_id is None or malicious_url is None:
            return None

        canonical_id = f"URLHAUS-{urlhaus_id}"

        source_reference = self._clean_string(
            entry.get("urlhaus_reference")
        )

        source_threat_type = self._clean_string(
            entry.get("threat")
        )

        url_status = self._clean_string(
            entry.get("url_status")
        )

        date_added = self._clean_string(
            entry.get("date_added")
        )

        last_online = self._clean_string(
            entry.get("last_online")
        )

        reporter = self._clean_string(
            entry.get("reporter")
        )

        host = self._clean_string(
            entry.get("host")
        )

        tags = self._normalize_string_list(
            entry.get("tags")
        )

        blacklists = self._normalize_dictionary(
            entry.get("blacklists")
        )

        larted = self._parse_bool(
            entry.get("larted")
        )

        payloads = entry.get("payloads")

        normalized_payloads = (
            payloads
            if isinstance(payloads, list)
            else []
        )

        indicators = self._build_indicators(
            malicious_url=malicious_url,
            host=host,
            url_status=url_status,
            date_added=date_added,
            last_online=last_online,
            reporter=reporter,
            larted=larted,
            blacklists=blacklists,
            tags=tags,
            payloads=normalized_payloads,
            urlhaus_id=urlhaus_id,
        )

        labels = self._build_labels(
            tags=tags,
            payloads=normalized_payloads,
        )

        title = self._build_title(
            host=host,
            labels=labels,
        )

        description = self._build_description(
            malicious_url=malicious_url,
            host=host,
            url_status=url_status,
            source_threat_type=source_threat_type,
            labels=labels,
        )

        references: List[str] = []

        if source_reference is not None:
            references.append(source_reference)

        source_urls: Dict[str, str] = {}

        if source_reference is not None:
            source_urls[self.SOURCE_NAME] = source_reference

        source_dates: Dict[str, str] = {}

        if date_added is not None:
            source_dates["date_added"] = date_added
            source_dates["first_seen"] = date_added

        if last_online is not None:
            source_dates["last_online"] = last_online

        return Threat(
            id=canonical_id,
            external_ids={
                "URLHAUS": [urlhaus_id],
            },
            title=title,
            description=description,
            advisory_type=source_threat_type,
            threat_type=self.NORMALIZED_THREAT_TYPE,
            source=self.SOURCE_NAME,
            indicators=indicators,
            labels=labels,
            references=references,
            source_urls=source_urls,
            source_dates=source_dates,
            raw=dict(entry),
        )

    # ============================================================
    # Indicator construction
    # ============================================================

    def _build_indicators(
        self,
        *,
        malicious_url: str,
        host: Optional[str],
        url_status: Optional[str],
        date_added: Optional[str],
        last_online: Optional[str],
        reporter: Optional[str],
        larted: Optional[bool],
        blacklists: Dict[str, Any],
        tags: List[str],
        payloads: List[Any],
        urlhaus_id: str,
    ) -> List[Indicator]:
        indicators: List[Indicator] = []

        url_metadata: Dict[str, Any] = {
            "source": self.SOURCE_NAME,
            "urlhaus_id": urlhaus_id,
        }

        self._set_if_not_none(
            url_metadata,
            "status",
            url_status,
        )
        self._set_if_not_none(
            url_metadata,
            "first_seen",
            date_added,
        )
        self._set_if_not_none(
            url_metadata,
            "last_online",
            last_online,
        )
        self._set_if_not_none(
            url_metadata,
            "reporter",
            reporter,
        )
        self._set_if_not_none(
            url_metadata,
            "provider_notified",
            larted,
        )

        if blacklists:
            url_metadata["blacklists"] = blacklists

        if tags:
            url_metadata["tags"] = list(tags)

        indicators.append(
            Indicator(
                type="url",
                value=malicious_url,
                metadata=url_metadata,
            )
        )

        normalized_host = host or self._extract_host(
            malicious_url
        )

        if normalized_host is not None:
            host_type = self._detect_host_type(
                normalized_host
            )

            if host_type is not None:
                indicators.append(
                    Indicator(
                        type=host_type,
                        value=normalized_host,
                        metadata={
                            "source": self.SOURCE_NAME,
                            "urlhaus_id": urlhaus_id,
                        },
                    )
                )

        indicators.extend(
            self._build_payload_indicators(
                payloads=payloads,
                urlhaus_id=urlhaus_id,
            )
        )

        return self._deduplicate_indicators(
            indicators
        )

    def _build_payload_indicators(
        self,
        *,
        payloads: List[Any],
        urlhaus_id: str,
    ) -> List[Indicator]:
        indicators: List[Indicator] = []

        for payload in payloads:
            if not isinstance(payload, dict):
                continue

            common_metadata = self._build_payload_metadata(
                payload=payload,
                urlhaus_id=urlhaus_id,
            )

            md5_hash = self._normalize_hash(
                payload.get("response_md5"),
                expected_length=32,
            )

            sha256_hash = self._normalize_hash(
                payload.get("response_sha256"),
                expected_length=64,
            )

            if md5_hash is not None:
                indicators.append(
                    Indicator(
                        type="md5",
                        value=md5_hash,
                        metadata=dict(common_metadata),
                    )
                )

            if sha256_hash is not None:
                indicators.append(
                    Indicator(
                        type="sha256",
                        value=sha256_hash,
                        metadata=dict(common_metadata),
                    )
                )

        return indicators

    def _build_payload_metadata(
        self,
        *,
        payload: Dict[str, Any],
        urlhaus_id: str,
    ) -> Dict[str, Any]:
        metadata: Dict[str, Any] = {
            "source": self.SOURCE_NAME,
            "urlhaus_id": urlhaus_id,
        }

        field_mapping = {
            "firstseen": "first_seen",
            "filename": "filename",
            "file_type": "file_type",
            "response_size": "response_size",
            "signature": "malware_signature",
            "imphash": "imphash",
            "ssdeep": "ssdeep",
            "tlsh": "tlsh",
            "magika": "magika",
            "urlhaus_download": "urlhaus_download",
        }

        for source_field, target_field in field_mapping.items():
            value = payload.get(source_field)

            if value is not None:
                metadata[target_field] = value

        virustotal = payload.get("virustotal")

        if isinstance(virustotal, dict):
            metadata["virustotal"] = dict(virustotal)

        return metadata

    # ============================================================
    # Optional detailed enrichment
    # ============================================================

    def _should_fetch_details(
        self,
        detail_requests: int,
    ) -> bool:
        if not self._enrich_with_details:
            return False

        if self._max_detail_requests is None:
            return True

        return detail_requests < self._max_detail_requests

    def _fetch_details_safely(
        self,
        summary: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        """
        Retrieve detailed URL information without failing the entire
        collection if one enrichment request fails.
        """
        urlhaus_id = self._normalize_identifier(
            summary.get("id")
        )

        if urlhaus_id is None:
            return None

        try:
            details = (
                self._connector.fetch_url_information_by_id(
                    urlhaus_id
                )
            )
        except Exception:
            # The summary record remains usable even if detailed
            # enrichment temporarily fails.
            return None

        if not isinstance(details, dict):
            return None

        if details.get("query_status") != "ok":
            return None

        return details

    @staticmethod
    def _merge_records(
        *,
        summary: Dict[str, Any],
        details: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Merge summary and detailed URLhaus records.

        Detailed fields take precedence, while fields available only
        in the summary response are retained.
        """
        merged = dict(summary)
        merged.update(details)

        return merged

    # ============================================================
    # Text construction
    # ============================================================

    def _build_title(
        self,
        *,
        host: Optional[str],
        labels: List[str],
    ) -> str:
        malware_signature = self._find_malware_label(
            labels
        )

        if malware_signature and host:
            return (
                f"{malware_signature} malware distribution "
                f"from {host}"
            )

        if malware_signature:
            return (
                f"{malware_signature} malware distribution URL"
            )

        if host:
            return f"Malware distribution URL on {host}"

        return self.DEFAULT_TITLE

    def _build_description(
        self,
        *,
        malicious_url: str,
        host: Optional[str],
        url_status: Optional[str],
        source_threat_type: Optional[str],
        labels: List[str],
    ) -> str:
        parts = [
            "URLhaus reported a URL used to distribute malware."
        ]

        if host is not None:
            parts.append(
                f"The observed host is {host}."
            )

        if url_status is not None:
            parts.append(
                f"The URL status is {url_status}."
            )

        if source_threat_type is not None:
            parts.append(
                "The URLhaus threat classification is "
                f"{source_threat_type}."
            )

        if labels:
            parts.append(
                "Associated tags are: "
                f"{', '.join(labels)}."
            )

        parts.append(
            "The original malicious URL is preserved as an "
            "indicator and must not be opened directly."
        )

        return " ".join(parts)

    @staticmethod
    def _find_malware_label(
        labels: List[str],
    ) -> Optional[str]:
        """
        Select a likely malware-family label for display purposes.

        URLhaus tags are heterogeneous. Technical tags are excluded
        from title generation, but all tags remain stored in labels.
        """
        technical_tags = {
            "32-bit",
            "64-bit",
            "arm",
            "arm5",
            "arm6",
            "arm7",
            "elf",
            "exe",
            "mips",
            "mips64",
            "pe",
            "x86",
            "x64",
        }

        for label in labels:
            if label.lower() not in technical_tags:
                return label

        return None

    # ============================================================
    # Normalization helpers
    # ============================================================

    @staticmethod
    def _normalize_identifier(
        value: Any,
    ) -> Optional[str]:
        if isinstance(value, bool):
            return None

        if isinstance(value, int):
            return str(value) if value >= 0 else None

        if isinstance(value, str):
            normalized = value.strip()

            if normalized.isdigit():
                return normalized

        return None

    @staticmethod
    def _clean_string(
        value: Any,
    ) -> Optional[str]:
        if not isinstance(value, str):
            return None

        normalized = value.strip()

        return normalized or None

    @classmethod
    def _normalize_string_list(
        cls,
        value: Any,
    ) -> List[str]:
        if not isinstance(value, list):
            return []

        normalized: List[str] = []

        for element in value:
            cleaned = cls._clean_string(element)

            if cleaned is not None:
                normalized.append(cleaned)

        return cls._deduplicate_strings(
            normalized
        )

    @staticmethod
    def _normalize_dictionary(
        value: Any,
    ) -> Dict[str, Any]:
        if not isinstance(value, dict):
            return {}

        return dict(value)

    @staticmethod
    def _parse_bool(
        value: Any,
    ) -> Optional[bool]:
        if isinstance(value, bool):
            return value

        if isinstance(value, str):
            normalized = value.strip().lower()

            if normalized in {"true", "1", "yes"}:
                return True

            if normalized in {"false", "0", "no"}:
                return False

        if isinstance(value, int) and value in {0, 1}:
            return bool(value)

        return None

    @staticmethod
    def _extract_host(
        url: str,
    ) -> Optional[str]:
        try:
            parsed = urlparse(url)
        except ValueError:
            return None

        hostname = parsed.hostname

        if not isinstance(hostname, str):
            return None

        hostname = hostname.strip()

        return hostname or None

    @staticmethod
    def _detect_host_type(
        host: str,
    ) -> Optional[str]:
        try:
            parsed_ip = ip_address(host)
        except ValueError:
            normalized_host = host.strip().lower()

            if not normalized_host:
                return None

            return "domain"

        if parsed_ip.version == 4:
            return "ipv4"

        return "ipv6"

    @staticmethod
    def _normalize_hash(
        value: Any,
        *,
        expected_length: int,
    ) -> Optional[str]:
        if not isinstance(value, str):
            return None

        normalized = value.strip().lower()

        if len(normalized) != expected_length:
            return None

        try:
            int(normalized, 16)
        except ValueError:
            return None

        return normalized

    @staticmethod
    def _set_if_not_none(
        target: Dict[str, Any],
        key: str,
        value: Any,
    ) -> None:
        if value is not None:
            target[key] = value

    @staticmethod
    def _deduplicate_strings(
        values: List[str],
    ) -> List[str]:
        seen: set[str] = set()
        result: List[str] = []

        for value in values:
            deduplication_key = value.lower()

            if deduplication_key in seen:
                continue

            seen.add(deduplication_key)
            result.append(value)

        return result

    @staticmethod
    def _deduplicate_indicators(
        indicators: List[Indicator],
    ) -> List[Indicator]:
        """
        Deduplicate indicators by normalized type and value.

        Indicator.metadata is intentionally excluded from equality in
        the domain object, but using an explicit key makes the rule
        clear here.
        """
        seen: set[tuple[str, str]] = set()
        result: List[Indicator] = []

        for indicator in indicators:
            key = (
                indicator.type.lower(),
                indicator.value,
            )

            if key in seen:
                continue

            seen.add(key)
            result.append(indicator)

        return result

    def _build_labels(
        self,
        *,
        tags: List[str],
        payloads: List[Any],
    ) -> List[str]:
        labels = list(tags)

        for payload in payloads:
            if not isinstance(payload, dict):
                continue

            for field_name in (
                "signature",
                "file_type",
                "magika",
            ):
                value = self._clean_string(
                    payload.get(field_name)
                )

                if value is not None:
                    labels.append(value)

        return self._deduplicate_strings(labels)