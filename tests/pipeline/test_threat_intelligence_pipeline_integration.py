from __future__ import annotations

import pytest

from application.services.cisa_threat_source import (
    CISAThreatSource,
)
from application.services.epss_enrichment_service import (
    EPSSEnrichmentService,
)
from application.services.github_advisory_threat_source import (
    GitHubAdvisoryThreatSource,
)
from application.services.mitre_threat_source import (
    MITREThreatSource,
)
from application.services.nvd_threat_source import (
    NVDThreatSource,
)
from application.services.threat_correlation_service import (
    ThreatCorrelationService,
)
from application.services.threat_intelligence_pipeline_service import (
    ThreatIntelligencePipelineResult,
    ThreatIntelligencePipelineService,
)
from infrastructure.persistence.mitre_sync_state import (
    MITRESyncState,
)


def display_real_pipeline_result(
    result: ThreatIntelligencePipelineResult,
) -> None:
    print(
        "\n"
        "=================================================="
    )
    print(
        "       REAL THREAT INTELLIGENCE PIPELINE"
    )
    print(
        "=================================================="
    )

    print("\n----- Global metadata -----")

    metadata_fields = [
        "status",
        "configured_sources",
        "successful_sources",
        "failed_sources",
        "total_source_records",
        "unique_threats",
        "multi_source_threats",
        "epss_status",
        "duration_seconds",
        "fusion_performed",
        "source_specific_records_preserved",
    ]

    for field_name in metadata_fields:
        print(
            f"{field_name:<36}: "
            f"{result.metadata.get(field_name)}"
        )

    print("\n----- Source summaries -----")

    for summary in result.metadata[
        "source_summaries"
    ]:
        print(
            f"{summary['source']:<22} "
            f"success={summary['success']} "
            f"threats={summary['threats']} "
            f"duration={summary['duration_seconds']}s"
        )

        if not summary["success"]:
            print(
                f"  Error: {summary['error_type']} - "
                f"{summary['error_message']}"
            )

    print("\n----- EPSS metadata -----")

    epss_metadata = result.metadata.get(
        "epss_metadata"
    )

    if epss_metadata:
        for key, value in epss_metadata.items():
            print(f"{key:<25}: {value}")
    else:
        print("No EPSS metadata available.")

    print("\n----- Multi-source groups -----")

    groups = result.multi_source_groups()

    if not groups:
        print(
            "No common vulnerability was found in the "
            "current source collection windows."
        )

    for group in groups[:10]:
        print(
            f"\nCVE ID       : {group.id}"
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
                f"\n  [{source_name}]"
            )

            for threat in threats:
                print(
                    f"    Title       : "
                    f"{threat.title or 'N/A'}"
                )

                description = (
                    threat.description
                    or "N/A"
                )

                if len(description) > 180:
                    description = (
                        description[:180]
                        + "..."
                    )

                print(
                    f"    Description : {description}"
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
                    f"    Weaknesses  : "
                    f"{len(threat.weaknesses)}"
                )
                print(
                    f"    References  : "
                    f"{len(threat.references)}"
                )

    print("\n----- Errors -----")

    if result.errors:
        for error in result.errors:
            print(error)
    else:
        print("No pipeline errors.")


@pytest.mark.integration
def test_complete_pipeline_with_real_sources(
    tmp_path,
) -> None:
    """
    Execute the complete real pipeline:

    NVD
    + CISA
    + MITRE
    + GitHub Advisory
    + correlation
    + EPSS enrichment

    The test validates orchestration and source compatibility.

    The deterministic unit test separately guarantees that
    multi-source synergy works when the sources contain the same CVE.
    """

    sync_file = (
        tmp_path
        / "mitre_pipeline_sync_state.json"
    )

    mitre_sync_state = MITRESyncState(
        filepath=str(sync_file)
    )

    sources = [
        NVDThreatSource(),
        CISAThreatSource(),
        MITREThreatSource(
            sync_state=mitre_sync_state
        ),
        GitHubAdvisoryThreatSource(),
    ]

    pipeline = ThreatIntelligencePipelineService(
        sources=sources,
        correlation_service=(
            ThreatCorrelationService()
        ),
        epss_enrichment_service=(
            EPSSEnrichmentService()
        ),
        fail_fast=False,
    )

    result = pipeline.run()

    display_real_pipeline_result(
        result
    )

    assert isinstance(
        result,
        ThreatIntelligencePipelineResult,
    )

    assert result.metadata["configured_sources"] == 4

    assert (
        result.metadata["successful_sources"]
        >= 1
    )

    assert (
        result.metadata["total_source_records"]
        > 0
    )

    assert result.metadata["unique_threats"] > 0

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

    assert isinstance(
        result.collection_results,
        list,
    )

    assert isinstance(
        result.correlation_result.groups,
        dict,
    )

    # Every correlated record must still be a source-specific
    # object stored inside its original source group.
    for group in result.correlation_result.all_groups():
        assert group.id

        assert len(group.threats) == sum(
            len(threats)
            for threats
            in group.threats_by_source.values()
        )

        for source_name in group.sources:
            assert source_name in (
                group.threats_by_source
            )