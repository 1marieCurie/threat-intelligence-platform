# after adding mitre, we test that all sources till now produce the same Threat Object
from domain.threat import Threat
from domain.collection_result import CollectionResult

from application.services.nvd_threat_source import NVDThreatSource
from application.services.cisa_threat_source import CISAThreatSource
from application.services.mitre_threat_source import MITREThreatSource

from infrastructure.persistence.mitre_sync_state import MITRESyncState


MITRE_TEST_FILEPATH = (
    "cves/2026/0xxx/"
    "CVE-2026-0964.json"
)


def _assert_valid_threat(threat: Threat):
    """
    Verifies that a Threat object respects the stable
    domain contract shared by all threat sources.
    """

    assert isinstance(threat, Threat)

    # Identity
    assert isinstance(threat.id, str)
    assert threat.id.startswith("CVE-")

    # Core information
    assert isinstance(threat.description, str)

    # Optional classification
    assert (
        threat.severity is None
        or isinstance(threat.severity, str)
    )

    assert (
        threat.cvss_score is None
        or isinstance(threat.cvss_score, (int, float))
    )
    
    # EPSS enrichment fields
    assert (
        threat.epss_score is None
        or isinstance(threat.epss_score, (int, float))
    )

    assert (
        threat.epss_percentile is None
        or isinstance(threat.epss_percentile, (int, float))
    )

    assert (
        threat.epss_date is None
        or isinstance(threat.epss_date, str)
    )

    # Collections
    assert isinstance(threat.affected_products, list)
    assert isinstance(threat.weaknesses, list)
    assert isinstance(threat.labels, list)
    assert isinstance(threat.references, list)

    # Optional enrichment fields
    assert (
        threat.known_exploited_date is None
        or isinstance(threat.known_exploited_date, str)
    )

    assert (
        threat.remediation is None
        or isinstance(threat.remediation, str)
    )

    assert (
        threat.ransomware_campaign_use is None
        or isinstance(threat.ransomware_campaign_use, str)
    )

    # Dates
    assert (
        threat.published_date is None
        or isinstance(threat.published_date, str)
    )

    assert (
        threat.last_modified_date is None
        or isinstance(threat.last_modified_date, str)
    )

    # Raw data
    assert isinstance(threat.raw, dict)



def test_nvd_threat_domain_stability():

    source = NVDThreatSource()

    result = source.collect()

    print("\n[DOMAIN STABILITY] NVD collection result")
    print(f"Collected threats: {len(result.threats)}")

    assert isinstance(result, CollectionResult)
    assert result.metadata["source"] == "NVD"

    assert len(result.threats) > 0

    threat = result.threats[0]

    print("\n[NVD Threat]")
    print(f"ID          : {threat.id}")
    print(f"Severity    : {threat.severity}")
    print(f"CVSS Score  : {threat.cvss_score}")
    print(f"References  : {len(threat.references)}")
    print(f"Weaknesses  : {len(threat.weaknesses)}")
    print(f"Products    : {len(threat.affected_products)}")

    _assert_valid_threat(threat)



def test_cisa_threat_domain_stability():

    source = CISAThreatSource()

    result = source.collect()

    print("\n[DOMAIN STABILITY] CISA collection result")
    print(f"Collected threats: {len(result.threats)}")

    assert isinstance(result, CollectionResult)
    assert result.metadata["source"] == "CISA"

    assert len(result.threats) > 0

    threat = result.threats[0]

    print("\n[CISA Threat]")
    print(f"ID                       : {threat.id}")
    print(f"Title                    : {threat.title}")
    print(f"Known exploited date     : {threat.known_exploited_date}")
    print(f"Ransomware campaign use  : {threat.ransomware_campaign_use}")
    print(f"References               : {len(threat.references)}")
    print(f"Weaknesses               : {len(threat.weaknesses)}")
    print(f"Products                 : {len(threat.affected_products)}")

    _assert_valid_threat(threat)



def test_mitre_threat_domain_stability(tmp_path):

    sync_file = (
        tmp_path /
        "mitre_sync_state.json"
    )

    sync_state = MITRESyncState(
        filepath=str(sync_file)
    )

    source = MITREThreatSource(
        sync_state=sync_state
    )

    record = source.connector.download_cve_record(
        MITRE_TEST_FILEPATH
    )

    threats = source.parse(
        [record]
    )

    print("\n[DOMAIN STABILITY] MITRE parsing result")
    print(f"Parsed threats: {len(threats)}")

    assert len(threats) == 1

    threat = threats[0]

    print("\n[MITRE Threat]")
    print(f"ID          : {threat.id}")
    print(f"Title       : {threat.title}")
    print(f"Severity    : {threat.severity}")
    print(f"CVSS Score  : {threat.cvss_score}")
    print(f"References  : {len(threat.references)}")
    print(f"Weaknesses  : {len(threat.weaknesses)}")
    print(f"Products    : {len(threat.affected_products)}")
    print(f"Labels      : {len(threat.labels)}")

    _assert_valid_threat(threat)



def test_domain_model_stable_across_nvd_cisa_mitre(tmp_path):

    """
    Verifies that NVD, CISA and MITRE all produce objects
    compatible with the same Threat domain model.
    """

    # NVD
    nvd_result = NVDThreatSource().collect()
    nvd_threat = nvd_result.threats[0]

    # CISA
    cisa_result = CISAThreatSource().collect()
    cisa_threat = cisa_result.threats[0]

    # MITRE
    sync_file = (
        tmp_path /
        "mitre_sync_state.json"
    )

    sync_state = MITRESyncState(
        filepath=str(sync_file)
    )

    mitre_source = MITREThreatSource(
        sync_state=sync_state
    )

    mitre_record = mitre_source.connector.download_cve_record(
        MITRE_TEST_FILEPATH
    )

    mitre_threat = mitre_source.parse(
        [mitre_record]
    )[0]

    threats = [
        nvd_threat,
        cisa_threat,
        mitre_threat
    ]

    print("\n[DOMAIN STABILITY] Multi-source Threat compatibility")
    print(f"Sources tested: NVD, CISA, MITRE")
    print(f"Threat objects tested: {len(threats)}")

    for threat in threats:

        print("\nThreat validated:")
        print(f"ID          : {threat.id}")
        print(f"Title       : {threat.title}")
        print(f"Severity    : {threat.severity}")
        print(f"CVSS Score  : {threat.cvss_score}")
        print(f"References  : {len(threat.references)}")
        print(f"Weaknesses  : {len(threat.weaknesses)}")
        print(f"Products    : {len(threat.affected_products)}")

        _assert_valid_threat(threat)