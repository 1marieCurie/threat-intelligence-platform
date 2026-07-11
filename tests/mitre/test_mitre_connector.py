from __future__ import annotations

from copy import deepcopy
from typing import Any

import pytest

from infrastructure.adapters.outbound.mitre_connector import (
    MITREConnector,
)


# ============================================================
# Fake HTTP response
# ============================================================


class FakeResponse:
    """
    Minimal fake replacement for requests.Response.
    """

    def __init__(
        self,
        payload: Any,
        status_code: int = 200,
    ) -> None:
        self._payload = payload
        self.status_code = status_code

    def json(self) -> Any:
        return deepcopy(self._payload)

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise RuntimeError(
                f"Fake HTTP error: {self.status_code}"
            )


# ============================================================
# Fake CVE record
# ============================================================


@pytest.fixture
def sample_mitre_record() -> dict[str, Any]:
    """
    Return a realistic MITRE CVE Record 5.x without accessing GitHub.
    """

    return {
        "dataType": "CVE_RECORD",
        "dataVersion": "5.2",
        "cveMetadata": {
            "cveId": "CVE-2026-0964",
            "assignerOrgId": (
                "11111111-2222-3333-4444-555555555555"
            ),
            "state": "PUBLISHED",
            "datePublished": "2026-01-10T10:00:00.000Z",
            "dateUpdated": "2026-01-11T12:00:00.000Z",
        },
        "containers": {
            "cna": {
                "providerMetadata": {
                    "orgId": (
                        "11111111-2222-3333-4444-555555555555"
                    ),
                    "shortName": "ExampleCNA",
                    "dateUpdated": (
                        "2026-01-11T12:00:00.000Z"
                    ),
                },
                "title": (
                    "Example product path sanitization "
                    "vulnerability"
                ),
                "descriptions": [
                    {
                        "lang": "en",
                        "value": (
                            "Example Product contains an improper "
                            "path sanitization vulnerability."
                        ),
                    }
                ],
                "affected": [
                    {
                        "vendor": "Example Vendor",
                        "product": "Example Product",
                        "versions": [
                            {
                                "version": "1.0.0",
                                "status": "affected",
                            },
                            {
                                "version": "2.0.0",
                                "status": "unaffected",
                            },
                        ],
                    }
                ],
                "problemTypes": [
                    {
                        "descriptions": [
                            {
                                "lang": "en",
                                "cweId": "CWE-22",
                                "description": (
                                    "Improper Limitation of a "
                                    "Pathname to a Restricted "
                                    "Directory"
                                ),
                                "type": "CWE",
                            }
                        ]
                    }
                ],
                "references": [
                    {
                        "url": (
                            "https://example.org/advisories/"
                            "CVE-2026-0964"
                        ),
                    },
                    {
                        "url": (
                            "https://example.org/patches/"
                            "CVE-2026-0964"
                        ),
                    },
                ],
                "metrics": [
                    {
                        "cvssV3_1": {
                            "version": "3.1",
                            "vectorString": (
                                "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/"
                                "S:U/C:L/I:L/A:L"
                            ),
                            "baseScore": 6.3,
                            "baseSeverity": "MEDIUM",
                        }
                    }
                ],
            },
            "adp": [],
        },
    }


# ============================================================
# Unit tests: no network
# ============================================================


def test_get_latest_commit_with_fake_response(
    monkeypatch,
) -> None:
    """
    Verify parsing of GitHub's latest-commit response without
    performing an HTTP request.
    """

    connector = MITREConnector()

    expected_commit = (
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    )

    fake_response = FakeResponse(
        [
            {
                "sha": expected_commit,
            }
        ]
    )

    def fake_get(*args, **kwargs):
        return fake_response

    monkeypatch.setattr(
        connector.session,
        "get",
        fake_get,
    )

    commit = connector.get_latest_commit()

    assert commit == expected_commit
    assert isinstance(commit, str)


def test_download_cve_record_with_fake_response(
    monkeypatch,
    sample_mitre_record: dict[str, Any],
) -> None:
    """
    Verify downloading and decoding a CVE record without GitHub.
    """

    connector = MITREConnector()

    fake_response = FakeResponse(
        sample_mitre_record
    )

    def fake_get(*args, **kwargs):
        return fake_response

    monkeypatch.setattr(
        connector.session,
        "get",
        fake_get,
    )

    record = connector.download_cve_record(
        "cves/2026/0xxx/CVE-2026-0964.json"
    )

    assert record == sample_mitre_record
    assert record["dataType"] == "CVE_RECORD"
    assert record["dataVersion"] == "5.2"

    assert (
        record["cveMetadata"]["cveId"]
        == "CVE-2026-0964"
    )


def test_cve_record_structure(
    sample_mitre_record: dict[str, Any],
) -> None:
    """
    Validate the mandatory CNA structure using local fake data.
    """

    cna = sample_mitre_record[
        "containers"
    ]["cna"]

    print(
        "\n[MITRE CONNECTOR] "
        "CNA mandatory fields validation"
    )
    print("Mandatory fields detected:")

    mandatory_fields = [
        "providerMetadata",
        "descriptions",
        "affected",
        "references",
    ]

    for field in mandatory_fields:
        print(f"  ✓ {field}")
        assert field in cna


def test_no_update_when_same_commit(
    monkeypatch,
) -> None:
    """
    If the saved commit is already the latest commit, no record
    should be downloaded.

    The GitHub request is replaced with a deterministic fake.
    """

    connector = MITREConnector()

    current_commit = (
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    )

    monkeypatch.setattr(
        connector,
        "get_latest_commit",
        lambda: current_commit,
    )

    new_commit, records = connector.fetch_new_records(
        current_commit
    )

    print(
        "\n[MITRE CONNECTOR] "
        "Incremental synchronization unit test"
    )
    print(f"Current commit: {current_commit}")
    print(f"New commit: {new_commit}")
    print(f"New records detected: {len(records)}")

    assert new_commit == current_commit
    assert records == []


def test_no_update_does_not_download_records(
    monkeypatch,
) -> None:
    """
    Ensure that download_cve_record is never called when the
    current commit is already synchronized.
    """

    connector = MITREConnector()

    current_commit = (
        "cccccccccccccccccccccccccccccccccccccccc"
    )

    monkeypatch.setattr(
        connector,
        "get_latest_commit",
        lambda: current_commit,
    )

    download_calls = 0

    def forbidden_download(filepath: str):
        nonlocal download_calls
        download_calls += 1

        raise AssertionError(
            "No record should be downloaded when commits match."
        )

    monkeypatch.setattr(
        connector,
        "download_cve_record",
        forbidden_download,
    )

    new_commit, records = connector.fetch_new_records(
        current_commit
    )

    assert new_commit == current_commit
    assert records == []
    assert download_calls == 0


# ============================================================
# Integration tests: real GitHub API
# ============================================================


@pytest.mark.integration
def test_integration_get_latest_commit() -> None:
    connector = MITREConnector()

    commit = connector.get_latest_commit()

    print(
        "\n[MITRE CONNECTOR] "
        "Latest repository commit retrieved successfully"
    )
    print(f"Commit SHA: {commit}")

    assert commit is not None
    assert isinstance(commit, str)
    assert len(commit) == 40


@pytest.mark.integration
def test_integration_download_cve_record() -> None:
    connector = MITREConnector()

    filepath = (
        "cves/2026/0xxx/"
        "CVE-2026-0964.json"
    )

    record = connector.download_cve_record(
        filepath
    )

    cve_id = record["cveMetadata"]["cveId"]

    print(
        "\n[MITRE CONNECTOR] "
        "CVE record downloaded successfully"
    )
    print(f"CVE ID: {cve_id}")
    print(f"Record type: {record['dataType']}")
    print(f"Record version: {record['dataVersion']}")

    assert record["dataType"] == "CVE_RECORD"
    assert "dataVersion" in record
    assert "cveMetadata" in record
    assert "containers" in record

    assert cve_id == "CVE-2026-0964"


@pytest.mark.integration
def test_integration_no_update_when_same_commit() -> None:
    """
    Minimal real synchronization test.

    This test consumes GitHub API requests and is therefore
    explicitly classified as integration.
    """

    connector = MITREConnector()

    current_commit = connector.get_latest_commit()

    new_commit, records = connector.fetch_new_records(
        current_commit
    )

    assert new_commit == current_commit
    assert records == []