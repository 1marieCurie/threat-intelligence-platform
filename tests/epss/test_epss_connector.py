from infrastructure.adapters.outbound.epss_connector import EPSSConnector


def test_fetch_single_cve_epss():

    connector = EPSSConnector()

    response = connector.fetch_by_cve(
        "CVE-2021-44228"
    )

    print("\n[EPSS CONNECTOR] Single CVE EPSS retrieval")
    print(f"Status      : {response.get('status')}")
    print(f"Status code : {response.get('status-code')}")
    print(f"Total       : {response.get('total')}")

    assert response is not None
    assert isinstance(response, dict)

    assert response.get("status") == "OK"
    assert response.get("status-code") == 200

    assert "data" in response
    assert isinstance(response["data"], list)

    assert response.get("total", 0) >= 1

    item = response["data"][0]

    print("\nReturned EPSS record:")
    print(f"CVE        : {item.get('cve')}")
    print(f"EPSS       : {item.get('epss')}")
    print(f"Percentile : {item.get('percentile')}")
    print(f"Date       : {item.get('date')}")

    assert item.get("cve") == "CVE-2021-44228"
    assert "epss" in item
    assert "percentile" in item
    assert "date" in item



def test_fetch_multiple_cves_epss():

    connector = EPSSConnector()

    cve_ids = [
        "CVE-2021-44228",
        "CVE-2024-4577"
    ]

    response = connector.fetch_by_cves(
        cve_ids
    )

    print("\n[EPSS CONNECTOR] Multiple CVE EPSS retrieval")
    print(f"Requested CVEs : {len(cve_ids)}")
    print(f"Returned total : {response.get('total')}")

    assert response is not None
    assert isinstance(response, dict)

    assert response.get("status") == "OK"
    assert response.get("status-code") == 200

    assert "data" in response
    assert isinstance(response["data"], list)

    returned_cves = [
        item.get("cve")
        for item in response["data"]
    ]

    print("Returned CVEs:")
    for cve in returned_cves:
        print(f"  - {cve}")

    assert "CVE-2021-44228" in returned_cves
    assert "CVE-2024-4577" in returned_cves



def test_epss_response_fields_are_valid():

    connector = EPSSConnector()

    response = connector.fetch_by_cve(
        "CVE-2021-44228"
    )

    item = response["data"][0]

    print("\n[EPSS CONNECTOR] Response field validation")
    print(f"CVE        : {item.get('cve')}")
    print(f"EPSS       : {item.get('epss')}")
    print(f"Percentile : {item.get('percentile')}")
    print(f"Date       : {item.get('date')}")

    assert isinstance(item.get("cve"), str)

    epss_score = float(
        item.get("epss")
    )

    percentile = float(
        item.get("percentile")
    )

    assert 0 <= epss_score <= 1
    assert 0 <= percentile <= 1

    assert isinstance(
        item.get("date"),
        str
    )



def test_clean_cve_ids():

    connector = EPSSConnector()

    cve_ids = [
        "cve-2021-44228",
        " CVE-2021-44228 ",
        "",
        None,
        "INVALID-ID",
        "CVE-2024-4577"
    ]

    cleaned = connector._clean_cve_ids(
        cve_ids
    )

    print("\n[EPSS CONNECTOR] CVE ID cleaning")
    print("Cleaned CVEs:")
    for cve in cleaned:
        print(f"  - {cve}")

    assert cleaned == [
        "CVE-2021-44228",
        "CVE-2024-4577"
    ]



def test_fetch_empty_cve_list_returns_empty_response():

    connector = EPSSConnector()

    response = connector.fetch_by_cves(
        []
    )

    print("\n[EPSS CONNECTOR] Empty CVE list handling")
    print(response)

    assert response["status"] == "OK"
    assert response["status-code"] == 200
    assert response["total"] == 0
    assert response["data"] == []



def test_build_cve_batches_respects_query_limit():

    connector = EPSSConnector()

    cve_ids = [
        f"CVE-2026-{str(i).zfill(4)}"
        for i in range(1, 300)
    ]

    batches = connector._build_cve_batches(
        cve_ids
    )

    print("\n[EPSS CONNECTOR] CVE batching validation")
    print(f"Input CVEs : {len(cve_ids)}")
    print(f"Batches    : {len(batches)}")

    for index, batch in enumerate(batches, start=1):

        query = ",".join(batch)

        print(
            f"Batch {index}: "
            f"{len(batch)} CVEs, "
            f"query length = {len(query)}"
        )

        assert len(query) <= connector.MAX_CVE_QUERY_LENGTH

    total_cves_in_batches = sum(
        len(batch)
        for batch in batches
    )

    assert total_cves_in_batches == len(cve_ids)



def test_fetch_by_batches():

    connector = EPSSConnector()

    cve_ids = [
        "CVE-2021-44228",
        "CVE-2024-4577",
        "CVE-2019-19781"
    ]

    responses = connector.fetch_by_batches(
        cve_ids
    )

    print("\n[EPSS CONNECTOR] Batch fetch validation")
    print(f"Number of API responses: {len(responses)}")

    assert isinstance(responses, list)
    assert len(responses) >= 1

    total_returned = 0

    for response in responses:

        assert response.get("status") == "OK"
        assert "data" in response

        total_returned += len(
            response["data"]
        )

    print(f"Total EPSS records returned: {total_returned}")

    assert total_returned >= 1