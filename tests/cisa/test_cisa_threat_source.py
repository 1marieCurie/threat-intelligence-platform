# tests/cisa/test_cisa_collection.py

import pytest

from application.services.cisa_threat_source import CISAThreatSource
from domain.collection_result import CollectionResult
from domain.threat import Threat
from domain.weakness_reference import WeaknessReference
from infrastructure.adapters.inbound.cisa_ingestion_job import (
    CISAIngestionJob,
)


@pytest.mark.integration
def test_cisa_collection() -> None:
    """
    Integration test for the complete CISA KEV ingestion pipeline.

    This test performs a real call to the CISA KEV catalog through:
        CISAConnector
            -> CISAThreatSource
            -> CISAIngestionJob

    It verifies:
    - collection metadata;
    - Threat object creation;
    - affected product normalization;
    - CWE normalization into WeaknessReference objects;
    - reference extraction;
    - CISA-specific intelligence fields.
    """

    source = CISAThreatSource()
    job = CISAIngestionJob(source)

    result = job.run()

    # =========================================================
    # CollectionResult validation
    # =========================================================

    assert isinstance(result, CollectionResult)
    assert isinstance(result.metadata, dict)
    assert isinstance(result.threats, list)

    # =========================================================
    # Metadata validation
    # =========================================================

    assert result.metadata.get("source") == "CISA"

    assert "title" in result.metadata
    assert "catalog_version" in result.metadata
    assert "date_released" in result.metadata
    assert "count" in result.metadata

    print("\n========== CISA COLLECTION METADATA ==========\n")

    for key, value in result.metadata.items():
        print(f"{key:<25}: {value}")

    # =========================================================
    # Collection summary
    # =========================================================

    print("\n========== CISA SUMMARY ==========\n")
    print(f"Collected threats : {len(result.threats)}")

    assert result.threats, (
        "The CISA KEV catalog did not return any vulnerability."
    )

    catalog_count = result.metadata.get("count")

    if isinstance(catalog_count, int):
        assert len(result.threats) == catalog_count

    # =========================================================
    # First parsed Threat validation
    # =========================================================

    first = result.threats[0]

    assert isinstance(first, Threat)

    assert isinstance(first.id, str)
    assert first.id.startswith("CVE-")

    assert first.source == "CISA"

    assert first.title is None or isinstance(
        first.title,
        str,
    )

    assert isinstance(first.description, str)
    assert isinstance(first.affected_products, list)
    assert isinstance(first.weakness_references, list)
    assert isinstance(first.references, list)
    assert isinstance(first.raw, dict)

    print("\n========== FIRST CISA THREAT ==========\n")

    print(f"ID                 : {first.id}")
    print(f"Source             : {first.source}")
    print(f"Title              : {first.title or 'N/A'}")
    print(f"Description        : {first.description}")
    print(f"Affected products  : {first.affected_products}")
    print(
        "Weakness references:",
        first.weakness_references,
    )
    print(f"References         : {len(first.references)}")

    # =========================================================
    # Affected products validation
    # =========================================================

    assert len(first.affected_products) == 1

    affected_product = first.affected_products[0]

    assert isinstance(affected_product, dict)
    assert "vendor" in affected_product
    assert "product" in affected_product

    assert (
        affected_product["vendor"]
        == first.raw.get("vendorProject")
    )

    assert (
        affected_product["product"]
        == first.raw.get("product")
    )

    # =========================================================
    # WeaknessReference validation
    # =========================================================

    for weakness_reference in first.weakness_references:
        assert isinstance(
            weakness_reference,
            WeaknessReference,
        )

        assert weakness_reference.source == "CISA"
        assert weakness_reference.origin == "cisa_kev"

        assert (
            weakness_reference.resolution_status
            == "resolved"
        )

        assert (
            weakness_reference.resolution_method
            == "explicit_id"
        )

        assert weakness_reference.cwe_id is not None
        assert weakness_reference.cwe_id.startswith(
            "CWE-"
        )

        assert isinstance(
            weakness_reference.raw,
            dict,
        )

        assert "value" in weakness_reference.raw

    # Verify that duplicate CWE identifiers were removed.
    normalized_cwe_ids = [
        weakness_reference.cwe_id
        for weakness_reference
        in first.weakness_references
    ]

    assert len(normalized_cwe_ids) == len(
        set(normalized_cwe_ids)
    )

    # =========================================================
    # Reference validation
    # =========================================================

    for reference in first.references:
        assert isinstance(reference, str)
        assert reference.strip()

    raw_notes = first.raw.get("notes", "")

    if raw_notes:
        expected_references = [
            note.strip()
            for note in raw_notes.split(";")
            if note.strip()
        ]

        assert first.references == expected_references

    # =========================================================
    # CISA intelligence validation
    # =========================================================

    assert (
        first.known_exploited_date
        == first.raw.get("dateAdded")
    )

    assert (
        first.ransomware_campaign_use
        == first.raw.get(
            "knownRansomwareCampaignUse"
        )
    )

    assert (
        first.remediation
        == first.raw.get("requiredAction")
    )

    print("\n========== CISA INTELLIGENCE ==========\n")

    print(
        f"Known exploited    : "
        f"{first.known_exploited_date}"
    )

    print(
        f"Ransomware use     : "
        f"{first.ransomware_campaign_use}"
    )

    print(
        f"Remediation        : "
        f"{first.remediation}"
    )

    # =========================================================
    # Raw CISA data
    # =========================================================

    print("\n========== RAW CISA DATA ==========\n")

    print(
        f"Date Added         : "
        f"{first.raw.get('dateAdded')}"
    )

    print(
        f"Vendor             : "
        f"{first.raw.get('vendorProject')}"
    )

    print(
        f"Product            : "
        f"{first.raw.get('product')}"
    )

    print(
        f"Vulnerability Name : "
        f"{first.raw.get('vulnerabilityName')}"
    )

    print(
        f"Due Date           : "
        f"{first.raw.get('dueDate')}"
    )

    print(
        f"Raw CWEs           : "
        f"{first.raw.get('cwes')}"
    )

    print(
        f"Normalized CWEs    : "
        f"{normalized_cwe_ids}"
    )

    print(
        f"Notes              : "
        f"{first.raw.get('notes')}"
    )