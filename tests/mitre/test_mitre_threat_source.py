from application.services.mitre_threat_source import MITREThreatSource
from domain.collection_result import CollectionResult
from domain.threat import Threat
from infrastructure.persistence.mitre_sync_state import MITRESyncState


FILEPATH = (
    "cves/2026/0xxx/"
    "CVE-2026-0964.json"
)


def _build_source(tmp_path):

    sync_file = (
        tmp_path /
        "mitre_sync_state.json"
    )

    sync_state = MITRESyncState(
        filepath=str(sync_file)
    )

    return MITREThreatSource(
        sync_state=sync_state
    )


def _load_record(source):

    return source.connector.download_cve_record(
        FILEPATH
    )


def test_parse_single_record(tmp_path):

    source = _build_source(tmp_path)

    record = _load_record(source)

    threat = source.parse([record])[0]

    print("\n[MITRE SERVICE] Successfully parsed one CVE Record")
    print(f"CVE ID      : {threat.id}")
    print(f"Title       : {threat.title}")
    print(f"Severity    : {threat.severity}")
    print(f"CVSS Score  : {threat.cvss_score}")
    print(f"Weaknesses  : {len(threat.weaknesses)}")
    print(f"References  : {len(threat.references)}")
    print(f"Products    : {len(threat.affected_products)}")

    assert isinstance(threat, Threat)

    assert threat.id == "CVE-2026-0964"

    assert threat.description != ""

    assert len(threat.references) > 0

    assert len(threat.affected_products) > 0


def test_parse_multiple_records(tmp_path):

    source = _build_source(tmp_path)

    record = _load_record(source)

    threats = source.parse(
        [record, record]
    )

    print("\n[MITRE SERVICE] Multiple records parsed successfully")
    print(f"Threats created: {len(threats)}")

    assert len(threats) == 2


def test_fetch_raw(tmp_path):

    source = _build_source(tmp_path)

    raw = source.fetch_raw()

    print("\n[MITRE SERVICE] fetch_raw() executed successfully")
    print(f"Previous commit : {raw['previous_commit']}")
    print(f"Current commit  : {raw['current_commit']}")
    print(f"Records fetched : {len(raw['records'])}")

    assert "previous_commit" in raw

    assert "current_commit" in raw

    assert "records" in raw


def test_collect_returns_collection_result(tmp_path):

    source = _build_source(tmp_path)

    result = source.collect()

    print("\n[MITRE SERVICE] collect() executed successfully")
    print(f"Threats collected: {len(result.threats)}")

    assert isinstance(
        result,
        CollectionResult
    )


def test_collect_metadata(tmp_path):

    source = _build_source(tmp_path)

    result = source.collect()

    print("\n[MITRE SERVICE] Collection metadata")

    for key, value in result.metadata.items():
        print(f"{key}: {value}")

    assert result.metadata["source"] == "MITRE"

    assert "current_commit" in result.metadata

    assert "records_collected" in result.metadata


def test_adp_enrichment(tmp_path):

    source = _build_source(tmp_path)

    record = _load_record(source)

    threat = source.parse([record])[0]

    print("\n[MITRE SERVICE] ADP enrichment verification")
    print(f"References : {len(threat.references)}")
    print(f"Weaknesses : {len(threat.weaknesses)}")
    print(f"Labels     : {len(threat.labels)}")

    assert threat.references is not None

    assert threat.weaknesses is not None

    assert threat.labels is not None
    
#synchronisation with an old commit
def test_incremental_synchronization(tmp_path):

    source = _build_source(tmp_path)

    latest_commit = source.connector.get_latest_commit()

    compare_url = (
        f"{source.connector.BASE_URL}/repos/"
        f"{source.connector.OWNER}/"
        f"{source.connector.REPO}/commits/{latest_commit}"
    )

    response = source.connector.session.get(compare_url)

    response.raise_for_status()

    parent_commit = (
        response.json()["parents"][0]["sha"]
    )

    source.sync_state.save_last_commit(
        parent_commit
    )

    result = source.collect()

    print("\n[MITRE SERVICE] Incremental synchronization")
    print(
        f"Previous commit : "
        f"{result.metadata['previous_commit']}"
    )
    print(
        f"Current commit  : "
        f"{result.metadata['current_commit']}"
    )
    print(
        f"Threats parsed  : "
        f"{len(result.threats)}"
    )

    assert (
        result.metadata["previous_commit"]
        !=
        result.metadata["current_commit"]
    )

# the commit is updated
def test_commit_state_updated(tmp_path):

    source = _build_source(tmp_path)

    result = source.collect()

    saved_commit = (
        source.sync_state.get_last_commit()
    )

    print("\n[MITRE SERVICE] Commit persistence")
    print(
        f"Saved commit : {saved_commit}"
    )

    assert (
        saved_commit
        ==
        result.metadata["current_commit"]
    )

# two conseutive comits
def test_second_synchronization_returns_no_records(tmp_path):

    source = _build_source(tmp_path)

    first = source.collect()

    second = source.collect()

    print(
        "\n[MITRE SERVICE] Consecutive synchronizations"
    )

    print(
        f"First synchronization : "
        f"{len(first.threats)} threat(s)"
    )

    print(
        f"Second synchronization : "
        f"{len(second.threats)} threat(s)"
    )

    assert len(second.threats) == 0

    assert (
        second.metadata["previous_commit"]
        ==
        second.metadata["current_commit"]
    )
    
# verify Threat objects
def test_all_threats_have_valid_identifier(tmp_path):

    source = _build_source(tmp_path)

    result = source.collect()

    print(
        "\n[MITRE SERVICE] Threat identifiers validation"
    )

    for threat in result.threats:

        print(threat.id)

        assert threat.id.startswith("CVE-")