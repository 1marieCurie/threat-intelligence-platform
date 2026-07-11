from __future__ import annotations

import pytest

from application.services.cisa_threat_source import (
    CISAThreatSource,
)
from application.services.nvd_threat_source import (
    NVDThreatSource,
)
from domain.collection_result import CollectionResult
from domain.threat import Threat


# ============================================================
# Display helper
# ============================================================


def display_threat(
    threat: Threat,
    source_name: str,
) -> None:
    """
    Display a normalized Threat object independently from its
    original intelligence source.
    """

    print(
        f"\n========== {source_name} THREAT ==========\n"
    )

    print(f"ID                : {threat.id}")
    print(
        f"Title             : "
        f"{threat.title or 'N/A'}"
    )

    description = threat.description or "N/A"

    if len(description) > 200:
        description = description[:200] + "..."

    print(f"Description       : {description}")

    print("\n----- Classification -----")

    print(
        f"Severity          : "
        f"{threat.severity or 'N/A'}"
    )

    print(
        f"CVSS Score        : {threat.cvss_score if threat.cvss_score is not None else 'N/A'}"
    )

    print(
        "Weaknesses        :",
        (
            ", ".join(threat.weaknesses)
            if threat.weaknesses
            else "N/A"
        ),
    )

    print("\n----- Affected Products -----")

    if threat.affected_products:
        for index, product in enumerate(
            threat.affected_products,
            start=1,
        ):
            vendor = (
                product.get("vendor")
                or "Unknown"
            )

            name = (
                product.get("product")
                or "Unknown"
            )

            print(f"{index}. Vendor : {vendor}")
            print(f"   Product: {name}")

            if product.get("platforms"):
                print(
                    "   Platforms : "
                    f"{product['platforms']}"
                )

            if product.get("versions"):
                print(
                    "   Versions  : "
                    f"{product['versions']}"
                )
    else:
        print("N/A")

    print("\n----- Threat Intelligence -----")

    print(
        "Known exploited : "
        f"{threat.known_exploited_date or 'N/A'}"
    )

    print(
        "Ransomware use  : "
        f"{threat.ransomware_campaign_use or 'N/A'}"
    )

    print(
        "Remediation     : "
        f"{threat.remediation or 'N/A'}"
    )

    print("\n----- References -----")

    if threat.references:
        print(f"Total : {len(threat.references)}")

        for reference in threat.references[:3]:
            print(f" - {reference}")

        if len(threat.references) > 3:
            remaining = len(threat.references) - 3

            print(
                f" ... ({remaining} more)"
            )
    else:
        print("N/A")

    print("\n----- Dates -----")

    print(
        "Published       : "
        f"{threat.published_date or 'N/A'}"
    )

    print(
        "Last modified   : "
        f"{threat.last_modified_date or 'N/A'}"
    )

    print("\n----- Raw Data -----")

    print(
        f"Number of keys  : {len(threat.raw)}"
    )

    print(
        "First keys      : "
        f"{list(threat.raw.keys())[:5]}"
    )


# ============================================================
# Fake normalized data
# ============================================================


def build_fake_nvd_result() -> CollectionResult:
    """
    Build a deterministic CollectionResult representing NVD.
    """

    threats = [
        Threat(
            id="CVE-2026-0001",
            description=(
                "A fake vulnerability collected from NVD."
            ),
            severity="HIGH",
            cvss_score=8.8,
            affected_products=[
                {
                    "vendor": "Example Vendor",
                    "product": "Example Product",
                    "platforms": [
                        "Windows",
                        "Linux",
                    ],
                    "versions": [
                        {
                            "version": "1.0.0",
                            "status": "affected",
                        }
                    ],
                }
            ],
            weaknesses=[
                "CWE-79",
            ],
            references=[
                "https://example.org/nvd/advisory",
                "https://example.org/nvd/patch",
            ],
            published_date=(
                "2026-07-01T10:00:00.000Z"
            ),
            last_modified_date=(
                "2026-07-02T12:00:00.000Z"
            ),
            raw={
                "id": "CVE-2026-0001",
                "sourceIdentifier": "nvd@example.org",
                "published": (
                    "2026-07-01T10:00:00.000Z"
                ),
                "lastModified": (
                    "2026-07-02T12:00:00.000Z"
                ),
                "vulnStatus": "Analyzed",
            },
        ),
        Threat(
            id="CVE-2026-0002",
            description="Second fake NVD vulnerability.",
            severity="MEDIUM",
            cvss_score=6.5,
            weaknesses=[
                "CWE-89",
            ],
            references=[
                "https://example.org/nvd/second",
            ],
            raw={
                "id": "CVE-2026-0002",
            },
        ),
        Threat(
            id="CVE-2026-0003",
            description="Third fake NVD vulnerability.",
            severity="LOW",
            cvss_score=3.1,
            weaknesses=[
                "CWE-200",
            ],
            references=[],
            raw={
                "id": "CVE-2026-0003",
            },
        ),
    ]

    return CollectionResult(
        threats=threats,
        metadata={
            "source": "NVD",
            "total_results": 3,
        },
    )


def build_fake_cisa_result() -> CollectionResult:
    """
    Build a deterministic CollectionResult representing CISA.
    """

    threats = [
        Threat(
            id="CVE-2026-0001",
            title=(
                "Example Product Known Exploited "
                "Vulnerability"
            ),
            description=(
                "A fake known exploited vulnerability "
                "collected from CISA."
            ),
            affected_products=[
                {
                    "vendor": "Example Vendor",
                    "product": "Example Product",
                }
            ],
            weaknesses=[
                "CWE-79",
            ],
            references=[
                "https://example.org/cisa/advisory",
                "https://example.org/cisa/remediation",
            ],
            known_exploited_date="2026-07-10",
            ransomware_campaign_use="Unknown",
            remediation=(
                "Apply the vendor-provided security update."
            ),
            raw={
                "cveID": "CVE-2026-0001",
                "vendorProject": "Example Vendor",
                "product": "Example Product",
                "dateAdded": "2026-07-10",
            },
        ),
        Threat(
            id="CVE-2026-0004",
            title="Second fake CISA vulnerability",
            description=(
                "Second fake known exploited vulnerability."
            ),
            known_exploited_date="2026-07-09",
            raw={
                "cveID": "CVE-2026-0004",
            },
        ),
        Threat(
            id="CVE-2026-0005",
            title="Third fake CISA vulnerability",
            description=(
                "Third fake known exploited vulnerability."
            ),
            known_exploited_date="2026-07-08",
            raw={
                "cveID": "CVE-2026-0005",
            },
        ),
    ]

    return CollectionResult(
        threats=threats,
        metadata={
            "source": "CISA",
            "count": 3,
        },
    )


# ============================================================
# Shared validation helper
# ============================================================


def validate_domain_independence(
    nvd_result: CollectionResult,
    cisa_result: CollectionResult,
) -> None:
    """
    Verify that threats from both sources expose the same domain
    attributes.
    """

    assert nvd_result.threats
    assert cisa_result.threats

    nvd_threat = nvd_result.threats[0]
    cisa_threat = cisa_result.threats[0]

    print("\n========== TYPE CHECK ==========\n")

    print(
        f"NVD object  : "
        f"{type(nvd_threat).__name__}"
    )

    print(
        f"CISA object : "
        f"{type(cisa_threat).__name__}"
    )

    assert isinstance(nvd_threat, Threat)
    assert isinstance(cisa_threat, Threat)

    display_threat(
        nvd_threat,
        "NVD",
    )

    display_threat(
        cisa_threat,
        "CISA",
    )

    print(
        "\n========== DOMAIN VALIDATION ==========\n"
    )

    required_fields = [
        "id",
        "external_ids",
        "title",
        "description",
        "advisory_type",
        "severity",
        "cvss_score",
        "cvss_metrics",
        "epss_score",
        "epss_percentile",
        "epss_date",
        "affected_products",
        "weaknesses",
        "weakness_details",
        "labels",
        "references",
        "source_urls",
        "source_code_locations",
        "known_exploited_date",
        "remediation",
        "ransomware_campaign_use",
        "published_date",
        "last_modified_date",
        "reviewed_date",
        "withdrawn_date",
        "source_dates",
        "raw",
        "risk_score",
        "embedding",
    ]

    for field_name in required_fields:
        assert hasattr(
            nvd_threat,
            field_name,
        )

        assert hasattr(
            cisa_threat,
            field_name,
        )

        print(f"{field_name:<25} OK")

    print(
        "\n✓ Threat domain is independent "
        "from the intelligence source."
    )


# ============================================================
# Unit test: fake data only
# ============================================================


def test_domain_independence_with_fake_data() -> None:
    """
    Unit test verifying the common Threat structure without
    external APIs.
    """

    print(
        "\n############ "
        "TESTING THREAT DOMAIN INDEPENDENCE "
        "WITH FAKE DATA "
        "############"
    )

    nvd_result = build_fake_nvd_result()
    cisa_result = build_fake_cisa_result()

    print(
        "\n========== FIRST 3 FAKE NVD THREATS =========="
    )

    for index, threat in enumerate(
        nvd_result.threats[:3],
        start=1,
    ):
        display_threat(
            threat,
            f"NVD #{index}",
        )

    print(
        "\n========== FIRST 3 FAKE CISA THREATS =========="
    )

    for index, threat in enumerate(
        cisa_result.threats[:3],
        start=1,
    ):
        display_threat(
            threat,
            f"CISA #{index}",
        )

    validate_domain_independence(
        nvd_result,
        cisa_result,
    )


# ============================================================
# Integration test: real NVD and CISA APIs
# ============================================================


@pytest.mark.integration
def test_domain_independence_with_real_sources() -> None:
    """
    Integration test using the real NVD and CISA services.
    """

    print(
        "\n############ "
        "TESTING THREAT DOMAIN INDEPENDENCE "
        "WITH REAL SOURCES "
        "############"
    )

    nvd_source = NVDThreatSource()
    cisa_source = CISAThreatSource()

    nvd_result = nvd_source.collect()
    cisa_result = cisa_source.collect()

    assert len(nvd_result.threats) >= 3
    assert len(cisa_result.threats) >= 3

    print(
        "\n========== FIRST 3 NVD THREATS =========="
    )

    for index, threat in enumerate(
        nvd_result.threats[:3],
        start=1,
    ):
        display_threat(
            threat,
            f"NVD #{index}",
        )

    print(
        "\n========== FIRST 3 CISA THREATS =========="
    )

    for index, threat in enumerate(
        cisa_result.threats[:3],
        start=1,
    ):
        display_threat(
            threat,
            f"CISA #{index}",
        )

    validate_domain_independence(
        nvd_result,
        cisa_result,
    )


if __name__ == "__main__":
    test_domain_independence_with_fake_data()