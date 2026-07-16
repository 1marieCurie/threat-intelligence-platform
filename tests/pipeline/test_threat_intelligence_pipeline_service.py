from __future__ import annotations

from copy import deepcopy
from typing import Any, List, Optional

from domain.indicator import Indicator
import pytest

from application.ports.inbound.threat_source import (
    ThreatSource,
)
from application.services.epss_enrichment_service import (
    EPSSEnrichmentResult,
    EPSSEnrichmentService,
)
from application.services.threat_correlation_service import (
    ThreatCorrelationResult,
    ThreatCorrelationService,
)
from application.services.threat_intelligence_pipeline_service import (
    SourceExecutionResult,
    ThreatIntelligencePipelineResult,
    ThreatIntelligencePipelineService,
)
from domain.collection_result import CollectionResult
from domain.threat import Threat
from domain.weakness_reference import WeaknessReference


COMMON_CVE = "CVE-2021-44228"


# ============================================================
# Fake sources
# ============================================================


class FakeThreatSource(ThreatSource):
    """
    Deterministic ThreatSource used to test the complete pipeline
    without accessing external APIs.
    """

    def __init__(
        self,
        source_name: str,
        threats: List[Threat],
        metadata: Optional[dict[str, Any]] = None,
    ) -> None:
        self._source_name = source_name
        self._threats = threats
        self._metadata = metadata or {}
        self.collect_calls = 0

    def name(self) -> str:
        return self._source_name

    def collect(self) -> CollectionResult:
        self.collect_calls += 1

        metadata = deepcopy(
            self._metadata
        )

        metadata.setdefault(
            "source",
            self._source_name,
        )

        return CollectionResult(
            threats=self._threats,
            metadata=metadata,
        )

    def fetch_raw(self) -> Any:
        return {
            "source": self._source_name,
        }

    def parse(
        self,
        raw_data: Any,
    ) -> List[Threat]:
        return self._threats


class FailingThreatSource(ThreatSource):
    """
    Fake source that always fails during collection.
    """

    def __init__(
        self,
        source_name: str = "FAILING_SOURCE",
    ) -> None:
        self._source_name = source_name
        self.collect_calls = 0

    def name(self) -> str:
        return self._source_name

    def collect(self) -> CollectionResult:
        self.collect_calls += 1

        raise ConnectionError(
            "Simulated source connection failure."
        )

    def fetch_raw(self) -> Any:
        raise ConnectionError(
            "Simulated source connection failure."
        )

    def parse(
        self,
        raw_data: Any,
    ) -> List[Threat]:
        return []


class InvalidResultThreatSource(ThreatSource):
    """
    Fake source returning an invalid value instead of CollectionResult.
    """

    def name(self) -> str:
        return "INVALID_SOURCE"

    def collect(self) -> CollectionResult:
        # Intentionally invalid for testing runtime validation.
        return "invalid result"  # type: ignore[return-value]

    def fetch_raw(self) -> Any:
        return None

    def parse(
        self,
        raw_data: Any,
    ) -> List[Threat]:
        return []


# ============================================================
# Fake EPSS service
# ============================================================


class FakeEPSSEnrichmentService(
    EPSSEnrichmentService
):
    """
    Deterministic EPSS enrichment service.

    It enriches every source-specific Threat representing
    CVE-2021-44228.
    """

    def __init__(self) -> None:
        # No real EPSSConnector is needed.
        self.enrichment_calls = 0
        self.received_dates: List[Optional[str]] = []

    def enrich_correlation_result(
        self,
        correlation_result: ThreatCorrelationResult,
        date: Optional[str] = None,
    ) -> EPSSEnrichmentResult:
        self.enrichment_calls += 1
        self.received_dates.append(date)

        all_threats: List[Threat] = []

        for group in correlation_result.all_groups():
            all_threats.extend(
                group.threats
            )

        enriched_count = 0

        for threat in all_threats:
            if threat.id != COMMON_CVE:
                continue

            threat.epss_score = 0.99999
            threat.epss_percentile = 1.0
            threat.epss_date = (
                date
                or "2026-07-11"
            )

            enriched_count += 1

        requested_cves = {
            threat.id
            for threat in all_threats
            if threat.id.startswith("CVE-")
        }

        missing_cves = sorted(
            cve_id
            for cve_id in requested_cves
            if cve_id != COMMON_CVE
        )

        non_cve_threats = sum(
            1
            for threat in all_threats
            if not threat.id.startswith("CVE-")
        )

        return EPSSEnrichmentResult(
            threats=all_threats,
            metadata={
                "source": "EPSS",
                "requested_cves": len(
                    requested_cves
                ),
                "epss_records_found": 1,
                "enriched_threats": enriched_count,
                "missing_cves": missing_cves,
                "non_cve_threats": non_cve_threats,
                "date_requested": date,
            },
        )


class FailingEPSSEnrichmentService(
    EPSSEnrichmentService
):
    """
    Fake EPSS service that simulates API failure.
    """

    def enrich_correlation_result(
        self,
        correlation_result: ThreatCorrelationResult,
        date: Optional[str] = None,
    ) -> EPSSEnrichmentResult:
        raise TimeoutError(
            "Simulated EPSS timeout."
        )


# ============================================================
# Fake source data
# ============================================================


def build_fake_sources() -> List[FakeThreatSource]:
    """
    Create four sources containing the same CVE, plus
    source-specific vulnerabilities.

    The common CVE demonstrates correlation without fusion.
    """

    nvd_threats = [
        Threat(
            id=COMMON_CVE,
            description=(
                "NVD description for Log4Shell."
            ),
            severity="CRITICAL",
            cvss_score=10.0,
            cvss_metrics={
                "3.1": {
                    "score": 10.0,
                    "vector": (
                        "CVSS:3.1/AV:N/AC:L/PR:N/"
                        "UI:N/S:C/C:H/I:H/A:H"
                    ),
                }
            },
            affected_products=[
                {
                    "vendor": "Apache",
                    "product": "Log4j",
                    "versions": [
                        {
                            "version": "2.0-beta9",
                            "status": "affected",
                        }
                    ],
                }
            ],
            weakness_references=[
                WeaknessReference(
                    source="NVD",
                    cwe_id="CWE-502",
                    resolution_status="resolved",
                    resolution_method="explicit_id",
                ),
            ],
            references=[
                "https://nvd.example/CVE-2021-44228",
            ],
            published_date=(
                "2021-12-10T10:15:00.000Z"
            ),
            raw={
                "sourceIdentifier": "nvd@nist.gov",
            },
        ),
        Threat(
            id="CVE-2026-1001",
            description="Threat available only in NVD.",
            severity="MEDIUM",
            cvss_score=6.5,
            raw={
                "source": "NVD",
            },
        ),
    ]

    cisa_threats = [
        Threat(
            id=COMMON_CVE,
            title=(
                "Apache Log4j2 Remote Code "
                "Execution Vulnerability"
            ),
            description=(
                "CISA KEV description for Log4Shell."
            ),
            known_exploited_date="2021-12-10",
            remediation=(
                "Apply updates according to vendor instructions."
            ),
            ransomware_campaign_use="Known",
            affected_products=[
                {
                    "vendor": "Apache",
                    "product": "Log4j2",
                }
            ],
            weakness_references=[
                WeaknessReference(
                    source="GITHUB_ADVISORY",
                    cwe_id="CWE-502",
                    resolution_status="resolved",
                    resolution_method="explicit_id",
                ),
            ],
            references=[
                "https://cisa.example/CVE-2021-44228",
            ],
            raw={
                "cveID": COMMON_CVE,
                "dateAdded": "2021-12-10",
            },
        ),
        Threat(
            id="CVE-2026-1002",
            title="Threat available only in CISA",
            description="CISA-only vulnerability.",
            known_exploited_date="2026-07-10",
            raw={
                "source": "CISA",
            },
        ),
    ]

    mitre_threats = [
        Threat(
            id=COMMON_CVE,
            title=(
                "Apache Log4j remote code execution"
            ),
            description=(
                "MITRE CNA description for Log4Shell."
            ),
            severity="CRITICAL",
            cvss_score=10.0,
            affected_products=[
                {
                    "vendor": "Apache Software Foundation",
                    "product": "Log4j",
                    "versions": [
                        {
                            "version": "2.0-beta9",
                            "status": "affected",
                        }
                    ],
                }
            ],
            references=[
                "https://mitre.example/CVE-2021-44228",
            ],
            source_dates={
                "cna_updated": (
                    "2021-12-10T00:00:00Z"
                ),
            },
            raw={
                "dataType": "CVE_RECORD",
            },
        ),
        Threat(
            id="CVE-2026-1003",
            description="MITRE-only vulnerability.",
            raw={
                "source": "MITRE",
            },
        ),
    ]

    github_threats = [
        Threat(
            id=COMMON_CVE,
            external_ids={
                "CVE": [
                    COMMON_CVE,
                ],
                "GHSA": [
                    "GHSA-jfh8-c2jp-5v3q",
                ],
            },
            title="Remote code injection in Log4j",
            description=(
                "GitHub Advisory description "
                "for Log4Shell."
            ),
            advisory_type="reviewed",
            severity="CRITICAL",
            cvss_score=10.0,
            affected_products=[
                {
                    "ecosystem": "MAVEN",
                    "package": (
                        "org.apache.logging.log4j:"
                        "log4j-core"
                    ),
                    "vulnerable_version_range": (
                        ">= 2.0-beta9, < 2.15.0"
                    ),
                }
            ],
            weakness_references=[
                WeaknessReference(
                    source="GITHUB_ADVISORY",
                    cwe_id="CWE-502",
                    resolution_status="resolved",
                    resolution_method="explicit_id",
                ),
            ],
            references=[
                (
                    "https://github.example/"
                    "GHSA-jfh8-c2jp-5v3q"
                ),
            ],
            source_urls={
                "github_advisory": (
                    "https://github.example/"
                    "GHSA-jfh8-c2jp-5v3q"
                ),
            },
            raw={
                "ghsa_id": "GHSA-jfh8-c2jp-5v3q",
            },
        ),
        Threat(
            id="GHSA-xxxx-yyyy-zzzz",
            external_ids={
                "GHSA": [
                    "GHSA-xxxx-yyyy-zzzz",
                ]
            },
            title="GHSA-only advisory",
            description=(
                "GitHub advisory without CVE identifier."
            ),
            advisory_type="reviewed",
            raw={
                "ghsa_id": "GHSA-xxxx-yyyy-zzzz",
            },
        ),
    ]
    
    urlhaus_threats = [
    Threat(
        id="URLHAUS-3886385",
        external_ids={
            "URLHAUS": [
                "3886385",
            ],
        },
        title=(
            "ClearFake malware distribution "
            "from malware.example.test"
        ),
        description=(
            "URLhaus reported an active malware "
            "distribution URL."
        ),
        advisory_type="malware_download",
        threat_type="malware_distribution",
        source="URLHAUS",
        indicators=[
            Indicator(
                type="url",
                value=(
                    "http://malware.example.test/"
                    "payload"
                ),
                metadata={
                    "source": "URLHAUS",
                    "urlhaus_id": "3886385",
                    "status": "online",
                },
            ),
            Indicator(
                type="domain",
                value="malware.example.test",
                metadata={
                    "source": "URLHAUS",
                    "urlhaus_id": "3886385",
                },
            ),
            Indicator(
                type="sha256",
                value="a" * 64,
                metadata={
                    "source": "URLHAUS",
                    "urlhaus_id": "3886385",
                    "malware_signature": "ClearFake",
                },
            ),
        ],
        labels=[
            "ClearFake",
            "windows",
        ],
        references=[
            (
                "https://urlhaus.abuse.ch/"
                "url/3886385/"
            ),
        ],
        source_urls={
            "URLHAUS": (
                "https://urlhaus.abuse.ch/"
                "url/3886385/"
            ),
        },
        source_dates={
            "date_added": (
                "2026-07-14 11:54:28 UTC"
            ),
            "first_seen": (
                "2026-07-14 11:54:28 UTC"
            ),
        },
        raw={
            "id": 3886385,
            "threat": "malware_download",
        },
    ),
]

    return [
        FakeThreatSource(
            source_name="NVD",
            threats=nvd_threats,
            metadata={
                "version": "2.0",
            },
        ),
        FakeThreatSource(
            source_name="CISA",
            threats=cisa_threats,
            metadata={
                "catalog_version": "2026.07.11",
            },
        ),
        FakeThreatSource(
            source_name="MITRE",
            threats=mitre_threats,
            metadata={
                "current_commit": "fake-commit",
            },
        ),
        FakeThreatSource(
            source_name="GITHUB_ADVISORY",
            threats=github_threats,
            metadata={
                "advisories_collected": 2,
            },
        ),
        FakeThreatSource(
            source_name="URLHAUS",
            threats=urlhaus_threats,
            metadata={
                "query_status": "ok",
                "received_records": 1,
                "parsed_threats": 1,
                "skipped_records": 0,
            },
        ),
    ]


# ============================================================
# Display helpers
# ============================================================


def display_pipeline_result(
    result: ThreatIntelligencePipelineResult,
) -> None:
    """
    Display a detailed representation of the pipeline output.
    """

    print(
        "\n"
        "=================================================="
    )
    print(
        "       THREAT INTELLIGENCE PIPELINE RESULT"
    )
    print(
        "=================================================="
    )

    print("\n----- Pipeline metadata -----")

    for key, value in result.metadata.items():
        if key == "source_summaries":
            continue

        print(f"{key:<35}: {value}")

    print("\n----- Source executions -----")

    for execution in result.source_executions:
        print(
            f"{execution.source_name:<20} "
            f"success={execution.success} "
            f"threats={execution.threats_count} "
            f"duration={execution.duration_seconds:.6f}s"
        )

        if not execution.success:
            print(
                f"  Error: {execution.error_type} - "
                f"{execution.error_message}"
            )

    print("\n----- Correlation groups -----")

    for group in result.correlation_result.all_groups():
        print(
            f"\nThreat ID    : {group.id}"
        )
        print(
            f"Sources      : {group.sources}"
        )
        print(
            f"Source count : {group.source_count}"
        )
        print(
            f"Records      : {len(group.threats)}"
        )

        for source_name, threats in (
            group.threats_by_source.items()
        ):
            print(
                f"\n  [{source_name}] "
                f"{len(threats)} record(s)"
            )

            for threat in threats:
                print(
                    f"    Title       : "
                    f"{threat.title or 'N/A'}"
                )
                print(
                    f"    Description : "
                    f"{threat.description or 'N/A'}"
                )
                print(
                    f"    Severity    : "
                    f"{threat.severity or 'N/A'}"
                )
                print(
                    f"    CVSS        : "
                    f"{threat.cvss_score if threat.cvss_score is not None else 'N/A'}"
                )
                print(
                    f"    EPSS        : "
                    f"{threat.epss_score if threat.epss_score is not None else 'N/A'}"
                )
                print(
                    f"    Products    : "
                    f"{len(threat.affected_products)}"
                )
                print(
                    f"    Weakness IDs: "
                    f"{threat.weakness_ids}"
                )
                print(
                    f"    References  : "
                    f"{len(threat.references)}"
                )

    print("\n----- EPSS metadata -----")

    if result.epss_enrichment_result is None:
        print("EPSS enrichment was not executed.")
    else:
        for key, value in (
            result
            .epss_enrichment_result
            .metadata
            .items()
        ):
            print(f"{key:<25}: {value}")

    print("\n----- Pipeline errors -----")

    if result.errors:
        for error in result.errors:
            print(error)
    else:
        print("No errors.")


# ============================================================
# Main synergy test
# ============================================================


def test_complete_pipeline_synergy_without_fusion() -> None:
    """
    Validate the complete deterministic pipeline:

    - four sources collect source-specific Threat objects;
    - one CVE is common to all sources;
    - correlation groups the four objects;
    - source-specific information is preserved;
    - no field-level fusion is performed;
    - EPSS enriches all four source-specific records.
    """

    sources = build_fake_sources()
    fake_epss = FakeEPSSEnrichmentService()

    pipeline = ThreatIntelligencePipelineService(
        sources=sources,
        correlation_service=(
            ThreatCorrelationService()
        ),
        epss_enrichment_service=fake_epss,
        fail_fast=False,
    )

    result = pipeline.run(
        epss_date="2026-07-11"
    )

    display_pipeline_result(
        result
    )

    assert isinstance(
        result,
        ThreatIntelligencePipelineResult,
    )

    # --------------------------------------------------------
    # Source execution
    # --------------------------------------------------------

    assert len(result.source_executions) == 5

    assert result.successful_sources() == [
        "NVD",
        "CISA",
        "MITRE",
        "GITHUB_ADVISORY",
        "URLHAUS",
    ]

    assert result.failed_sources() == []

    for source in sources:
        assert source.collect_calls == 1

    # --------------------------------------------------------
    # Global statistics
    # --------------------------------------------------------

    assert result.metadata["status"] == "SUCCESS"
    assert result.metadata["configured_sources"] == 5
    assert result.metadata["successful_sources"] == 5
    assert result.metadata["failed_sources"] == 0

    # Two records from each of four sources.
    assert result.metadata["total_source_records"] == 9

    # Common CVE + three source-only CVEs + one GHSA-only ID.
    assert result.metadata["unique_threats"] == 6

    assert (
        result.metadata["multi_source_threats"]
        == 1
    )

    assert (
        result.metadata["fusion_performed"]
        is False
    )

    assert (
        result.metadata[
            "source_specific_records_preserved"
        ]
        is True
    )

    # --------------------------------------------------------
    # Common CVE correlation group
    # --------------------------------------------------------

    group = result.get_group(
        COMMON_CVE
    )

    assert group is not None
    assert group.id == COMMON_CVE
    assert group.is_multi_source is True
    assert group.source_count == 4

    assert set(group.sources) == {
        "NVD",
        "CISA",
        "MITRE",
        "GITHUB_ADVISORY",
    }

    assert len(group.threats) == 4

    assert set(group.threats_by_source) == {
        "NVD",
        "CISA",
        "MITRE",
        "GITHUB_ADVISORY",
    }
    
    

    # --------------------------------------------------------
    # Source-specific information is preserved
    # --------------------------------------------------------

    nvd_threat = (
        group.threats_by_source["NVD"][0]
    )

    cisa_threat = (
        group.threats_by_source["CISA"][0]
    )

    mitre_threat = (
        group.threats_by_source["MITRE"][0]
    )

    github_threat = (
        group
        .threats_by_source["GITHUB_ADVISORY"][0]
    )

    assert nvd_threat.description == (
        "NVD description for Log4Shell."
    )
    assert nvd_threat.cvss_score == 10.0
    assert nvd_threat.severity == "CRITICAL"

    assert cisa_threat.description == (
        "CISA KEV description for Log4Shell."
    )
    assert (
        cisa_threat.known_exploited_date
        == "2021-12-10"
    )
    assert (
        cisa_threat.ransomware_campaign_use
        == "Known"
    )
    assert cisa_threat.cvss_score is None

    assert mitre_threat.description == (
        "MITRE CNA description for Log4Shell."
    )
    assert (
        mitre_threat.title
        == "Apache Log4j remote code execution"
    )

    assert github_threat.description == (
        "GitHub Advisory description "
        "for Log4Shell."
    )
    assert (
        github_threat.external_ids["GHSA"]
        == ["GHSA-jfh8-c2jp-5v3q"]
    )
    assert (
        github_threat.affected_products[0][
            "ecosystem"
        ]
        == "MAVEN"
    )

    # The four descriptions are preserved separately.
    assert {
        threat.description
        for threat in group.threats
    } == {
        "NVD description for Log4Shell.",
        "CISA KEV description for Log4Shell.",
        "MITRE CNA description for Log4Shell.",
        (
            "GitHub Advisory description "
            "for Log4Shell."
        ),
    }

    # --------------------------------------------------------
    # EPSS enrichment
    # --------------------------------------------------------

    assert fake_epss.enrichment_calls == 1
    assert fake_epss.received_dates == [
        "2026-07-11",
    ]

    for threat in group.threats:
        assert threat.epss_score == 0.99999
        assert threat.epss_percentile == 1.0
        assert threat.epss_date == "2026-07-11"

    assert result.epss_enrichment_result is not None

    assert (
        result.epss_enrichment_result.metadata[
            "enriched_threats"
        ]
        == 4
    )

    assert (
        result.epss_enrichment_result.metadata[
            "non_cve_threats"
        ]
        == 2
    )

    assert result.metadata["epss_status"] == "SUCCESS"

    # --------------------------------------------------------
    # Pipeline result helper methods
    # --------------------------------------------------------

    assert len(result.all_threats()) == 9
    assert len(result.unique_ids()) == 6
    assert len(result.multi_source_groups()) == 1
    assert result.errors == []


# ============================================================
# Object identity test
# ============================================================


def test_epss_updates_original_source_objects() -> None:
    """
    Verify that EPSS enriches the same Threat instances that are
    preserved in CollectionResult and correlation groups.
    """

    sources = build_fake_sources()

    pipeline = ThreatIntelligencePipelineService(
        sources=sources,
        epss_enrichment_service=(
            FakeEPSSEnrichmentService()
        ),
    )

    result = pipeline.run()

    group = result.get_group(
        COMMON_CVE
    )

    assert group is not None

    correlated_nvd_threat = (
        group.threats_by_source["NVD"][0]
    )

    original_nvd_threat = (
        result.collection_results[0].threats[0]
    )

    assert (
        correlated_nvd_threat
        is original_nvd_threat
    )

    assert (
        original_nvd_threat.epss_score
        == 0.99999
    )


# ============================================================
# EPSS skip test
# ============================================================


def test_pipeline_can_skip_epss_enrichment() -> None:
    sources = build_fake_sources()
    fake_epss = FakeEPSSEnrichmentService()

    pipeline = ThreatIntelligencePipelineService(
        sources=sources,
        epss_enrichment_service=fake_epss,
    )

    result = pipeline.run(
        enrich_with_epss=False
    )

    assert fake_epss.enrichment_calls == 0

    assert (
        result.epss_enrichment_result
        is None
    )

    assert (
        result.metadata["epss_status"]
        == "SKIPPED"
    )

    group = result.get_group(
        COMMON_CVE
    )

    assert group is not None

    for threat in group.threats:
        assert threat.epss_score is None
        assert threat.epss_percentile is None
        assert threat.epss_date is None


# ============================================================
# Partial source failure test
# ============================================================


def test_pipeline_continues_when_one_source_fails() -> None:
    sources: List[ThreatSource] = [
        *build_fake_sources(),
        FailingThreatSource(
            "BROKEN_SOURCE"
        ),
    ]

    pipeline = ThreatIntelligencePipelineService(
        sources=sources,
        epss_enrichment_service=(
            FakeEPSSEnrichmentService()
        ),
        fail_fast=False,
    )

    result = pipeline.run()

    assert result.metadata["status"] == (
        "PARTIAL_SUCCESS"
    )

    assert result.metadata["configured_sources"] == 6
    assert result.metadata["successful_sources"] == 5
    assert result.metadata["failed_sources"] == 1

    assert result.failed_sources() == [
        "BROKEN_SOURCE",
    ]

    assert len(result.errors) == 1

    error = result.errors[0]

    assert error["stage"] == "COLLECTION"
    assert error["source"] == "BROKEN_SOURCE"
    assert error["error_type"] == (
        "ConnectionError"
    )

    # Successful source records remain available.
    assert result.get_group(COMMON_CVE) is not None


# ============================================================
# Fail-fast test
# ============================================================


def test_pipeline_fail_fast_raises_source_error() -> None:
    pipeline = ThreatIntelligencePipelineService(
        sources=[
            FailingThreatSource(),
        ],
        epss_enrichment_service=(
            FakeEPSSEnrichmentService()
        ),
        fail_fast=True,
    )

    with pytest.raises(
        ConnectionError,
        match="Simulated source connection failure",
    ):
        pipeline.run()


# ============================================================
# Invalid source result test
# ============================================================


def test_invalid_source_result_is_recorded() -> None:
    pipeline = ThreatIntelligencePipelineService(
        sources=[
            InvalidResultThreatSource(),
        ],
        epss_enrichment_service=(
            FakeEPSSEnrichmentService()
        ),
        fail_fast=False,
    )

    result = pipeline.run()

    assert result.metadata["status"] == "FAILED"
    assert result.metadata["successful_sources"] == 0
    assert result.metadata["failed_sources"] == 1

    assert result.failed_sources() == [
        "INVALID_SOURCE",
    ]

    assert len(result.errors) == 1

    assert (
        result.errors[0]["error_type"]
        == "TypeError"
    )


# ============================================================
# EPSS failure test
# ============================================================


def test_pipeline_records_epss_failure() -> None:
    pipeline = ThreatIntelligencePipelineService(
        sources=build_fake_sources(),
        epss_enrichment_service=(
            FailingEPSSEnrichmentService()
        ),
        fail_fast=False,
    )

    result = pipeline.run()

    assert result.metadata["status"] == (
        "PARTIAL_SUCCESS"
    )

    assert result.metadata["epss_status"] == (
        "FAILED"
    )

    assert (
        result.epss_enrichment_result
        is None
    )

    assert len(result.errors) == 1

    assert result.errors[0]["stage"] == "EPSS"
    assert (
        result.errors[0]["error_type"]
        == "TimeoutError"
    )

    # Collection and correlation still succeeded.
    assert result.get_group(COMMON_CVE) is not None


def test_pipeline_fail_fast_raises_epss_error() -> None:
    pipeline = ThreatIntelligencePipelineService(
        sources=build_fake_sources(),
        epss_enrichment_service=(
            FailingEPSSEnrichmentService()
        ),
        fail_fast=True,
    )

    with pytest.raises(
        TimeoutError,
        match="Simulated EPSS timeout",
    ):
        pipeline.run()