# application/services/phishtank_threat_source.py

from __future__ import annotations

from ipaddress import ip_address
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from application.ports.inbound.threat_source import ThreatSource
from domain.collection_result import CollectionResult
from domain.indicator import Indicator
from domain.threat import Threat
from domain.threat_category import ThreatCategory
from infrastructure.adapters.outbound.phishtank_connector import (
    PhishTankConnector,
)


class PhishTankThreatSource(ThreatSource):
    """
    Application service responsible for collecting and
    normalizing phishing intelligence from PhishTank.

    The PhishTank connector retrieves raw records from the
    downloadable JSON snapshot.

    This service converts those source-specific dictionaries
    into normalized phishing Threat objects.
    """

    SOURCE_NAME = "PHISHTANK"

    THREAT_CATEGORY = (
        ThreatCategory.PHISHING
    )

    def __init__(
        self,
        connector: Optional[
            PhishTankConnector
        ] = None,
        *,
        limit: Optional[int] = None,
        force_download: bool = False,
    ) -> None:
        """
        Initialize the PhishTank threat source.

        Args:
            connector:
                Connector used to retrieve raw PhishTank data.

            limit:
                Optional maximum number of records to collect.

            force_download:
                Force the connector to download a fresh snapshot,
                even when the remote ETag has not changed.
        """

        if isinstance(limit, bool):
            raise TypeError(
                "limit must be an integer or None."
            )

        if limit is not None:
            if not isinstance(limit, int):
                raise TypeError(
                    "limit must be an integer or None."
                )

            if limit < 0:
                raise ValueError(
                    "limit must be greater than or equal to zero."
                )

        self.connector = (
            connector
            or PhishTankConnector()
        )

        self.limit = limit
        self.force_download = force_download

    # ============================================================
    # Source contract
    # ============================================================

    def name(self) -> str:
        """
        Return the normalized source name.
        """

        return self.SOURCE_NAME

    def fetch_raw(
        self,
    ) -> List[Dict[str, Any]]:
        """
        Retrieve raw PhishTank records through the connector.
        """

        return self.connector.fetch_raw(
            force_download=self.force_download,
            limit=self.limit,
        )

    def parse(
        self,
        raw_data: Any,
    ) -> List[Threat]:
        """
        Convert raw PhishTank records into phishing Threat objects.

        Invalid top-level elements are skipped safely.

        Records without a usable PhishTank identifier or URL
        are also skipped because they cannot produce a valid
        normalized threat.
        """

        if not isinstance(raw_data, list):
            raise ValueError(
                "PhishTank raw data must be a list."
            )

        threats: List[Threat] = []

        for raw_record in raw_data:
            if not isinstance(
                raw_record,
                dict,
            ):
                continue

            threat = self._map_record_to_threat(
                raw_record
            )

            if threat is not None:
                threats.append(threat)

        return threats

    def collect(self) -> CollectionResult:
        """
        Collect raw records, normalize them and return a
        CollectionResult.
        """

        raw_data = self.fetch_raw()
        threats = self.parse(raw_data)

        sync_state = (
            self.connector.get_local_state()
        )

        metadata: Dict[str, Any] = {
            "source": self.name(),
            "category": (
                self.THREAT_CATEGORY.value
            ),
            "raw_record_count": len(
                raw_data
            ),
            "threat_count": len(
                threats
            ),
            "skipped_record_count": (
                len(raw_data)
                - len(threats)
            ),
            "limit": self.limit,
            "force_download": (
                self.force_download
            ),
            "verified_only": True,
            "online_only": True,
        }

        if isinstance(sync_state, dict):
            metadata.update(
                {
                    "etag": sync_state.get(
                        "etag"
                    ),
                    "last_modified": (
                        sync_state.get(
                            "last_modified"
                        )
                    ),
                    "content_length": (
                        sync_state.get(
                            "content_length"
                        )
                    ),
                    "downloaded_at": (
                        sync_state.get(
                            "downloaded_at"
                        )
                    ),
                    "dump_path": (
                        sync_state.get(
                            "dump_path"
                        )
                    ),
                    "downloaded": (
                        sync_state.get(
                            "downloaded"
                        )
                    ),
                    "used_local_snapshot": (
                        sync_state.get(
                            "used_local_snapshot"
                        )
                    ),
                }
            )

        return CollectionResult(
            threats=threats,
            metadata=metadata,
        )

    # ============================================================
    # Mapping
    # ============================================================

    def _map_record_to_threat(
        self,
        raw_record: Dict[str, Any],
    ) -> Optional[Threat]:
        """
        Map one raw PhishTank record to a normalized phishing
        Threat.

        Returns None when the record has no usable identifier
        or phishing URL.
        """

        phish_id = self._normalize_phish_id(
            raw_record.get(
                "phish_id"
            )
        )

        phishing_url = (
            self._normalize_string(
                raw_record.get("url")
            )
        )

        if (
            phish_id is None
            or phishing_url is None
        ):
            return None

        phish_detail_url = (
            self._normalize_string(
                raw_record.get(
                    "phish_detail_url"
                )
            )
        )

        submission_time = (
            self._normalize_string(
                raw_record.get(
                    "submission_time"
                )
            )
        )

        verification_time = (
            self._normalize_string(
                raw_record.get(
                    "verification_time"
                )
            )
        )

        verified = self._normalize_boolean(
            raw_record.get(
                "verified"
            )
        )

        online = self._normalize_boolean(
            raw_record.get(
                "online"
            )
        )

        target = self._normalize_string(
            raw_record.get(
                "target"
            )
        )

        indicators = self._extract_indicators(
            phishing_url=phishing_url,
            raw_details=raw_record.get(
                "details"
            ),
            verified=verified,
            online=online,
        )

        labels = self._build_labels(
            verified=verified,
            online=online,
            target=target,
        )

        references: List[str] = []

        if phish_detail_url:
            references.append(
                phish_detail_url
            )

        title = self._build_title(
            target=target,
            verified=verified,
            online=online,
        )

        description = (
            self._build_description(
                target=target,
                verified=verified,
                online=online,
            )
        )

        source_urls: Dict[
            str,
            str,
        ] = {}

        if phish_detail_url:
            source_urls[
                self.SOURCE_NAME
            ] = phish_detail_url

        source_dates: Dict[
            str,
            str,
        ] = {}

        if submission_time:
            source_dates[
                "submission_time"
            ] = submission_time

        if verification_time:
            source_dates[
                "verification_time"
            ] = verification_time

        return Threat(
            id=f"PHISHTANK-{phish_id}",
            category=self.THREAT_CATEGORY,
            source=self.SOURCE_NAME,
            external_ids={
                "PHISHTANK": [
                    str(phish_id)
                ],
            },
            title=title,
            description=description,
            indicators=indicators,
            labels=labels,
            references=references,
            source_urls=source_urls,
            published_date=(
                submission_time
            ),
            reviewed_date=(
                verification_time
            ),
            source_dates=source_dates,
            raw=dict(raw_record),
        )

    # ============================================================
    # Indicator extraction
    # ============================================================

    def _extract_indicators(
        self,
        *,
        phishing_url: str,
        raw_details: Any,
        verified: Optional[bool],
        online: Optional[bool],
    ) -> List[Indicator]:
        """
        Extract URL, domain, IP and CIDR indicators from one
        PhishTank record.
        """

        indicators: List[
            Indicator
        ] = []

        observation_metadata = (
            self._build_observation_metadata(
                verified=verified,
                online=online,
            )
        )

        self._append_indicator_if_unique(
            indicators,
            Indicator(
                type="url",
                value=phishing_url,
                confidence=(
                    1.0
                    if verified is True
                    else None
                ),
                metadata=dict(
                    observation_metadata
                ),
            ),
        )

        hostname = self._extract_hostname(
            phishing_url
        )

        if hostname:
            hostname_type = (
                self._detect_ip_type(
                    hostname
                )
            )

            indicator_type = (
                hostname_type
                if hostname_type
                is not None
                else "domain"
            )

            hostname_metadata = {
                **observation_metadata,
                "derived_from": "url",
            }

            self._append_indicator_if_unique(
                indicators,
                Indicator(
                    type=indicator_type,
                    value=hostname,
                    confidence=(
                        1.0
                        if verified is True
                        else None
                    ),
                    metadata=(
                        hostname_metadata
                    ),
                ),
            )

        if not isinstance(
            raw_details,
            list,
        ):
            return indicators

        for detail in raw_details:
            if not isinstance(
                detail,
                dict,
            ):
                continue

            ip_address_value = (
                self._normalize_string(
                    detail.get(
                        "ip_address"
                    )
                )
            )

            cidr_block = (
                self._normalize_string(
                    detail.get(
                        "cidr_block"
                    )
                )
            )

            network_metadata = (
                self._build_network_metadata(
                    raw_detail=detail,
                    verified=verified,
                    online=online,
                )
            )

            if ip_address_value:
                indicator_type = (
                    self._detect_ip_type(
                        ip_address_value
                    )
                )

                if (
                    indicator_type
                    is not None
                ):
                    self._append_indicator_if_unique(
                        indicators,
                        Indicator(
                            type=indicator_type,
                            value=(
                                ip_address_value
                            ),
                            confidence=(
                                1.0
                                if verified
                                is True
                                else None
                            ),
                            metadata=dict(
                                network_metadata
                            ),
                        ),
                    )

            if cidr_block:
                self._append_indicator_if_unique(
                    indicators,
                    Indicator(
                        type="cidr",
                        value=cidr_block,
                        confidence=(
                            1.0
                            if verified is True
                            else None
                        ),
                        metadata=dict(
                            network_metadata
                        ),
                    ),
                )

        return indicators

    @staticmethod
    def _append_indicator_if_unique(
        indicators: List[Indicator],
        candidate: Indicator,
    ) -> None:
        """
        Append an indicator only when the same type and value
        are not already present.
        """

        candidate_key = (
            candidate.type,
            candidate.value,
        )

        existing_keys = {
            (
                indicator.type,
                indicator.value,
            )
            for indicator in indicators
        }

        if (
            candidate_key
            not in existing_keys
        ):
            indicators.append(
                candidate
            )

    def _build_observation_metadata(
        self,
        *,
        verified: Optional[bool],
        online: Optional[bool],
    ) -> Dict[str, Any]:
        """
        Build common metadata describing the observable status.
        """

        metadata: Dict[
            str,
            Any,
        ] = {
            "source": self.SOURCE_NAME,
        }

        if verified is not None:
            metadata[
                "verified"
            ] = verified

        if online is not None:
            metadata[
                "online"
            ] = online

        return metadata

    def _build_network_metadata(
        self,
        *,
        raw_detail: Dict[str, Any],
        verified: Optional[bool],
        online: Optional[bool],
    ) -> Dict[str, Any]:
        """
        Preserve useful PhishTank network context.
        """

        metadata = (
            self._build_observation_metadata(
                verified=verified,
                online=online,
            )
        )

        optional_fields = {
            "cidr_block": (
                "cidr_block"
            ),
            "announcing_network": (
                "announcing_network"
            ),
            "rir": "rir",
            "country": "country",
            "detail_time": (
                "detail_time"
            ),
        }

        for (
            source_key,
            metadata_key,
        ) in optional_fields.items():
            value = self._normalize_string(
                raw_detail.get(
                    source_key
                )
            )

            if value is not None:
                metadata[
                    metadata_key
                ] = value

        return metadata

    # ============================================================
    # Title, description and labels
    # ============================================================

    def _build_title(
        self,
        *,
        target: Optional[str],
        verified: Optional[bool],
        online: Optional[bool],
    ) -> str:
        """
        Build a readable phishing title.
        """

        target_label = (
            target
            if (
                target
                and target.lower()
                != "other"
            )
            else "unknown target"
        )

        if (
            verified is True
            and online is True
        ):
            return (
                "Verified online phishing URL "
                f"targeting {target_label}"
            )

        if verified is True:
            return (
                "Verified phishing URL "
                f"targeting {target_label}"
            )

        return (
            "Phishing URL targeting "
            f"{target_label}"
        )

    @staticmethod
    def _build_description(
        *,
        target: Optional[str],
        verified: Optional[bool],
        online: Optional[bool],
    ) -> str:
        """
        Build a readable phishing description.
        """

        target_description = (
            target
            if target
            else "an unspecified service"
        )

        verification_description = (
            "verified"
            if verified is True
            else "reported"
        )

        online_description = (
            "currently online"
            if online is True
            else (
                "not confirmed as "
                "currently online"
            )
        )

        return (
            f"A {verification_description} "
            "phishing URL targeting "
            f"{target_description} was "
            "reported by PhishTank and is "
            f"{online_description}."
        )

    def _build_labels(
        self,
        *,
        verified: Optional[bool],
        online: Optional[bool],
        target: Optional[str],
    ) -> List[str]:
        """
        Build descriptive phishing labels.
        """

        labels = [
            "phishing",
            "malicious-url",
        ]

        if verified is True:
            labels.append(
                "verified"
            )

        elif verified is False:
            labels.append(
                "unverified"
            )

        if online is True:
            labels.append(
                "online"
            )

        elif online is False:
            labels.append(
                "offline"
            )

        if target:
            normalized_target = (
                target
                .strip()
                .lower()
                .replace(" ", "-")
            )

            labels.append(
                f"target:{normalized_target}"
            )

        return self._deduplicate_strings(
            labels
        )

    # ============================================================
    # Normalization helpers
    # ============================================================

    @staticmethod
    def _normalize_phish_id(
        value: Any,
    ) -> Optional[int]:
        """
        Normalize a PhishTank identifier.
        """

        if isinstance(value, bool):
            return None

        try:
            phish_id = int(value)

        except (
            TypeError,
            ValueError,
        ):
            return None

        if phish_id <= 0:
            return None

        return phish_id

    @staticmethod
    def _normalize_string(
        value: Any,
    ) -> Optional[str]:
        """
        Normalize an optional source value to a non-empty string.
        """

        if value is None:
            return None

        if not isinstance(
            value,
            str,
        ):
            value = str(value)

        normalized = (
            value
            .replace("\u00a0", " ")
            .strip()
        )

        return normalized or None

    @staticmethod
    def _normalize_boolean(
        value: Any,
    ) -> Optional[bool]:
        """
        Normalize PhishTank boolean representations.
        """

        if isinstance(value, bool):
            return value

        if not isinstance(value, str):
            return None

        normalized = (
            value
            .strip()
            .lower()
        )

        if normalized in {
            "yes",
            "y",
            "true",
            "1",
        }:
            return True

        if normalized in {
            "no",
            "n",
            "false",
            "0",
        }:
            return False

        return None

    @staticmethod
    def _extract_hostname(
        url: str,
    ) -> Optional[str]:
        """
        Extract a normalized hostname from a URL.
        """

        try:
            hostname = (
                urlparse(url).hostname
            )

        except ValueError:
            return None

        if not hostname:
            return None

        return (
            hostname
            .strip()
            .lower()
            or None
        )

    @staticmethod
    def _detect_ip_type(
        value: str,
    ) -> Optional[str]:
        """
        Detect whether a value is a valid IPv4 or IPv6 address.
        """

        try:
            parsed_ip = ip_address(
                value
            )

        except ValueError:
            return None

        if parsed_ip.version == 4:
            return "ipv4"

        return "ipv6"

    @staticmethod
    def _deduplicate_strings(
        values: List[str],
    ) -> List[str]:
        """
        Remove duplicate strings while preserving their order.
        """

        result: List[str] = []
        seen: set[str] = set()

        for value in values:
            if value in seen:
                continue

            result.append(value)
            seen.add(value)

        return result