from infrastructure.adapters.outbound.mitre_connector import MITREConnector



def test_get_latest_commit():

    connector = MITREConnector()

    commit = connector.get_latest_commit()

    print("\n[MITRE CONNECTOR] Latest repository commit retrieved successfully:")
    print(f"Commit SHA: {commit}")


    assert commit is not None
    assert isinstance(commit, str)
    assert len(commit) > 0



def test_download_cve_record():

    connector = MITREConnector()


    filepath = (
        "cves/2026/0xxx/"
        "CVE-2026-0964.json"
    )


    record = connector.download_cve_record(
        filepath
    )


    cve_id = record["cveMetadata"]["cveId"]


    print("\n[MITRE CONNECTOR] CVE record downloaded successfully:")
    print(f"CVE ID: {cve_id}")
    print(f"Record type: {record['dataType']}")
    print(f"Record version: {record['dataVersion']}")


    assert record is not None

    assert (
        record["dataType"]
        ==
        "CVE_RECORD"
    )

    assert (
        "dataVersion"
        in record
    )

    assert (
        "cveMetadata"
        in record
    )

    assert (
        "containers"
        in record
    )



def test_cve_record_structure():

    connector = MITREConnector()


    filepath = (
        "cves/2026/0xxx/"
        "CVE-2026-0964.json"
    )


    record = connector.download_cve_record(
        filepath
    )


    cna = record["containers"]["cna"]


    print("\n[MITRE CONNECTOR] CNA mandatory fields validation:")
    print("Mandatory fields detected:")

    for field in [
        "providerMetadata",
        "descriptions",
        "affected",
        "references"
    ]:
        print(f"  ✓ {field}")


    assert "providerMetadata" in cna
    assert "descriptions" in cna
    assert "affected" in cna
    assert "references" in cna



def test_no_update_when_same_commit():

    connector = MITREConnector()


    current_commit = connector.get_latest_commit()


    new_commit, records = (
        connector.fetch_new_records(
            current_commit
        )
    )


    print("\n[MITRE CONNECTOR] Incremental synchronization test:")
    print(f"Current commit: {current_commit}")
    print(f"New commit: {new_commit}")
    print(f"New records detected: {len(records)}")


    assert (
        new_commit
        ==
        current_commit
    )


    assert (
        records
        ==
        []
    )