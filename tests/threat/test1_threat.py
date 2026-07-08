from application.services.nvd_threat_source import NVDThreatSource
from application.services.cisa_threat_source import CISAThreatSource


def display_threat(threat, source_name):

    print(f"\n========== {source_name} THREAT ==========\n")

    print(f"ID                : {threat.id}")
    print(f"Title             : {threat.title or 'N/A'}")

    description = threat.description or "N/A"
    if len(description) > 200:
        description = description[:200] + "..."
    print(f"Description       : {description}")

    print("\n----- Classification -----")

    print(f"Severity          : {threat.severity or 'N/A'}")
    print(f"CVSS Score        : {threat.cvss_score if threat.cvss_score is not None else 'N/A'}")

    print(
        "Weaknesses        :",
        ", ".join(threat.weaknesses) if threat.weaknesses else "N/A"
    )

    print("\n----- Affected Products -----")

    if threat.affected_products:

        for index, product in enumerate(threat.affected_products, start=1):

            vendor = product.get("vendor") or "Unknown"
            name = product.get("product") or "Unknown"

            print(f"{index}. Vendor : {vendor}")
            print(f"   Product: {name}")

            if product.get("platforms"):
                print(f"   Platforms : {product['platforms']}")

            if product.get("versions"):
                print(f"   Versions  : {product['versions']}")

    else:
        print("N/A")

    print("\n----- Threat Intelligence -----")

    print(
        f"Known exploited : {threat.known_exploited_date or 'N/A'}"
    )

    print(
        f"Ransomware use  : {threat.ransomware_campaign_use or 'N/A'}"
    )

    print(
        f"Remediation     : {threat.remediation or 'N/A'}"
    )

    print("\n----- References -----")

    if threat.references:

        print(f"Total : {len(threat.references)}")

        for reference in threat.references[:3]:
            print(f" - {reference}")

        if len(threat.references) > 3:
            print(f" ... ({len(threat.references)-3} more)")

    else:
        print("N/A")

    print("\n----- Dates -----")

    print(f"Published       : {threat.published_date or 'N/A'}")
    print(f"Last modified   : {threat.last_modified_date or 'N/A'}")

    print("\n----- Raw Data -----")

    print(f"Number of keys  : {len(threat.raw)}")
    print(f"First keys      : {list(threat.raw.keys())[:5]}")


def test_domain_independence():

    print("\n############ TESTING THREAT DOMAIN INDEPENDENCE ############")

    nvd_source = NVDThreatSource()
    cisa_source = CISAThreatSource()

    nvd_result = nvd_source.collect()
    cisa_result = cisa_source.collect()

    print("\n========== FIRST 3 NVD THREATS ==========")

    for i in range(3):
        display_threat(nvd_result.threats[i], f"NVD #{i+1}")

    print("\n========== FIRST 3 CISA THREATS ==========")

    for i in range(3):
        display_threat(cisa_result.threats[i], f"CISA #{i+1}")

    # On garde un Threat pour les assertions de validation
    nvd_threat = nvd_result.threats[0]
    cisa_threat = cisa_result.threats[0]
    
    print("\n========== TYPE CHECK ==========\n")

    print(f"NVD object  : {type(nvd_threat).__name__}")
    print(f"CISA object : {type(cisa_threat).__name__}")

    assert type(nvd_threat).__name__ == "Threat"
    assert type(cisa_threat).__name__ == "Threat"

    display_threat(nvd_threat, "NVD")
    display_threat(cisa_threat, "CISA")

    print("\n========== DOMAIN VALIDATION ==========\n")

    required_fields = [
        "id",
        "title",
        "description",
        "severity",
        "cvss_score",
        "affected_products",
        "weaknesses",
        "references",
        "known_exploited_date",
        "remediation",
        "ransomware_campaign_use",
        "published_date",
        "last_modified_date",
        "raw",
    ]

    for field in required_fields:

        assert hasattr(nvd_threat, field)
        assert hasattr(cisa_threat, field)

        print(f"{field:<25} OK")

    print("\n✓ Threat domain is independent from the intelligence source.")


if __name__ == "__main__":
    test_domain_independence()