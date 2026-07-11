from __future__ import annotations

from copy import deepcopy
from typing import Any

import pytest

from application.services.mitre_threat_source import (
    MITREThreatSource,
)
from domain.collection_result import CollectionResult
from domain.threat import Threat
from infrastructure.persistence.mitre_sync_state import (
    MITRESyncState,
)
from infrastructure.adapters.outbound.mitre_connector import (
    MITREConnector,
)


FILEPATH = (
    "cves/2026/0xxx/"
    "CVE-2026-0964.json"
)

OLD_COMMIT = (
    "1111111111111111111111111111111111111111"
)

CURRENT_COMMIT = (
    "2222222222222222222222222222222222222222"
)


# ============================================================
# Fake CVE record
# ============================================================


@pytest.fixture
def sample_mitre_record() -> dict[str, Any]:
    """
    Return a realistic MITRE CVE Record compatible with the
    MITREThreatSource parser.
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
                        "platforms": [
                            "Linux",
                            "Windows",
                        ],
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
            "adp": [
                {
                    "providerMetadata": {
                        "orgId": (
                            "22222222-3333-4444-5555-"
                            "666666666666"
                        ),
                        "shortName": "ExampleADP",
                        "dateUpdated": (
                            "2026-01-12T12:00:00.000Z"
                        ),
                    },
                    "references": [
                        {
                            "url": (
                                "https://example.org/"
                                "additional-analysis"
                            ),
                        }
                    ],
                    "problemTypes": [
                        {
                            "descriptions": [
                                {
                                    "lang": "en",
                                    "cweId": "CWE-22",
                                    "description": (
                                        "Path traversal"
                                    ),
                                    "type": "CWE",
                                }
                            ]
                        }
                    ],
                }
            ],
        },
    }


# ============================================================
# Fake connector
# ============================================================


class FakeMITREConnector(MITREConnector):
    """
    Deterministic replacement for MITREConnector.

    It respects the MITREConnector type while replacing all network
    operations with local fake data.
    """

    def __init__(
        self,
        records: list[dict[str, Any]],
        current_commit: str = CURRENT_COMMIT,
    ) -> None:
        # We intentionally do not call super().__init__(),
        # because this fake connector does not need a real HTTP session.
        self.records = deepcopy(records)
        self.current_commit = current_commit

        self.fetch_new_records_calls = 0
        self.download_calls = 0
        self.latest_commit_calls = 0

    def get_latest_commit(self) -> str:
        self.latest_commit_calls += 1

        return self.current_commit

    def download_cve_record(
        self,
        filepath: str,
    ) -> dict[str, Any]:
        self.download_calls += 1

        if not self.records:
            raise ValueError(
                "No fake MITRE record is configured."
            )

        return deepcopy(self.records[0])

    def fetch_new_records(
        self,
        last_commit: str | None,
    ) -> tuple[str, list[dict[str, Any]]]:
        self.fetch_new_records_calls += 1

        if last_commit == self.current_commit:
            return self.current_commit, []

        return (
            self.current_commit,
            deepcopy(self.records),
        )

# ============================================================
# Source builder
# ============================================================


def _build_source(
    tmp_path,
    records: list[dict[str, Any]],
    current_commit: str = CURRENT_COMMIT,
) -> tuple[MITREThreatSource, FakeMITREConnector]:
    """
    Build MITREThreatSource with temporary persistence and a fake
    MITREConnector.
    """

    sync_file = (
        tmp_path
        / "mitre_sync_state.json"
    )

    sync_state = MITRESyncState(
        filepath=str(sync_file)
    )

    source = MITREThreatSource(
        sync_state=sync_state
    )

    fake_connector = FakeMITREConnector(
        records=records,
        current_commit=current_commit,
    )

    source.connector = fake_connector

    return source, fake_connector

# ============================================================
# Unit tests: parsing
# ============================================================


def test_parse_single_record(
    tmp_path,
    sample_mitre_record: dict[str, Any],
) -> None:
    source, _ = _build_source(
        tmp_path,
        [sample_mitre_record],
    )

    threat = source.parse(
        [deepcopy(sample_mitre_record)]
    )[0]

    print(
        "\n[MITRE SERVICE] "
        "Successfully parsed one fake CVE Record"
    )
    print(f"CVE ID      : {threat.id}")
    print(f"Title       : {threat.title}")
    print(f"Severity    : {threat.severity}")
    print(f"CVSS Score  : {threat.cvss_score}")
    print(f"Weaknesses  : {len(threat.weaknesses)}")
    print(f"References  : {len(threat.references)}")
    print(
        "Products    : "
        f"{len(threat.affected_products)}"
    )

    assert isinstance(threat, Threat)

    assert threat.id == "CVE-2026-0964"

    assert threat.title == (
        "Example product path sanitization "
        "vulnerability"
    )

    assert threat.description != ""
    assert threat.severity == "MEDIUM"
    assert threat.cvss_score == 6.3

    assert len(threat.references) > 0
    assert len(threat.affected_products) == 1
    assert (
    "Improper Limitation of a Pathname "
    "to a Restricted Directory"
    in threat.weaknesses
    )

    assert "Path traversal" in threat.weaknesses


def test_parse_multiple_records(
    tmp_path,
    sample_mitre_record: dict[str, Any],
) -> None:
    source, _ = _build_source(
        tmp_path,
        [sample_mitre_record],
    )

    second_record = deepcopy(
        sample_mitre_record
    )

    second_record["cveMetadata"]["cveId"] = (
        "CVE-2026-9999"
    )

    threats = source.parse(
        [
            deepcopy(sample_mitre_record),
            second_record,
        ]
    )

    print(
        "\n[MITRE SERVICE] "
        "Multiple fake records parsed successfully"
    )
    print(f"Threats created: {len(threats)}")

    assert len(threats) == 2

    assert [
        threat.id
        for threat in threats
    ] == [
        "CVE-2026-0964",
        "CVE-2026-9999",
    ]


def test_adp_enrichment(
    tmp_path,
    sample_mitre_record: dict[str, Any],
) -> None:
    source, _ = _build_source(
        tmp_path,
        [sample_mitre_record],
    )

    threat = source.parse(
        [deepcopy(sample_mitre_record)]
    )[0]

    print(
        "\n[MITRE SERVICE] "
        "ADP enrichment verification"
    )
    print(f"References : {len(threat.references)}")
    print(f"Weaknesses : {len(threat.weaknesses)}")
    print(f"Labels     : {len(threat.labels)}")

    assert threat.references is not None
    assert threat.weaknesses is not None
    assert threat.labels is not None

    assert (
        "https://example.org/additional-analysis"
        in threat.references
    )


# ============================================================
# Unit tests: synchronization and collection
# ============================================================


def test_fetch_raw_with_fake_connector(
    tmp_path,
    sample_mitre_record: dict[str, Any],
) -> None:
    source, fake_connector = _build_source(
        tmp_path,
        [sample_mitre_record],
    )

    raw = source.fetch_raw()

    print(
        "\n[MITRE SERVICE] "
        "fetch_raw() with fake connector"
    )
    print(
        "Previous commit : "
        f"{raw['previous_commit']}"
    )
    print(
        "Current commit  : "
        f"{raw['current_commit']}"
    )
    print(
        "Records fetched : "
        f"{len(raw['records'])}"
    )

    assert raw["previous_commit"] is None
    assert raw["current_commit"] == CURRENT_COMMIT
    assert len(raw["records"]) == 1

    assert fake_connector.fetch_new_records_calls == 1


def test_collect_returns_collection_result(
    tmp_path,
    sample_mitre_record: dict[str, Any],
) -> None:
    source, _ = _build_source(
        tmp_path,
        [sample_mitre_record],
    )

    result = source.collect()

    print(
        "\n[MITRE SERVICE] "
        "collect() with fake connector"
    )
    print(
        f"Threats collected: {len(result.threats)}"
    )

    assert isinstance(
        result,
        CollectionResult,
    )

    assert len(result.threats) == 1
    assert isinstance(result.threats[0], Threat)


def test_collect_metadata(
    tmp_path,
    sample_mitre_record: dict[str, Any],
) -> None:
    source, _ = _build_source(
        tmp_path,
        [sample_mitre_record],
    )

    result = source.collect()

    print("\n[MITRE SERVICE] Collection metadata")

    for key, value in result.metadata.items():
        print(f"{key}: {value}")

    assert result.metadata["source"] == "MITRE"

    assert (
        result.metadata["previous_commit"]
        is None
    )

    assert (
        result.metadata["current_commit"]
        == CURRENT_COMMIT
    )

    assert (
        result.metadata["records_collected"]
        == 1
    )


def test_incremental_synchronization(
    tmp_path,
    sample_mitre_record: dict[str, Any],
) -> None:
    """
    Simulate synchronization from an old commit without GitHub.
    """

    source, fake_connector = _build_source(
        tmp_path,
        [sample_mitre_record],
    )

    source.sync_state.save_last_commit(
        OLD_COMMIT
    )

    result = source.collect()

    print(
        "\n[MITRE SERVICE] "
        "Fake incremental synchronization"
    )
    print(
        "Previous commit : "
        f"{result.metadata['previous_commit']}"
    )
    print(
        "Current commit  : "
        f"{result.metadata['current_commit']}"
    )
    print(
        "Threats parsed  : "
        f"{len(result.threats)}"
    )

    assert (
        result.metadata["previous_commit"]
        == OLD_COMMIT
    )

    assert (
        result.metadata["current_commit"]
        == CURRENT_COMMIT
    )

    assert (
        result.metadata["previous_commit"]
        != result.metadata["current_commit"]
    )

    assert len(result.threats) == 1
    assert fake_connector.fetch_new_records_calls == 1


def test_commit_state_updated(
    tmp_path,
    sample_mitre_record: dict[str, Any],
) -> None:
    source, _ = _build_source(
        tmp_path,
        [sample_mitre_record],
    )

    result = source.collect()

    saved_commit = (
        source.sync_state.get_last_commit()
    )

    print("\n[MITRE SERVICE] Commit persistence")
    print(f"Saved commit : {saved_commit}")

    assert saved_commit == CURRENT_COMMIT

    assert (
        saved_commit
        == result.metadata["current_commit"]
    )


def test_second_synchronization_returns_no_records(
    tmp_path,
    sample_mitre_record: dict[str, Any],
) -> None:
    source, fake_connector = _build_source(
        tmp_path,
        [sample_mitre_record],
    )

    first = source.collect()
    second = source.collect()

    print(
        "\n[MITRE SERVICE] "
        "Consecutive fake synchronizations"
    )

    print(
        "First synchronization : "
        f"{len(first.threats)} threat(s)"
    )

    print(
        "Second synchronization : "
        f"{len(second.threats)} threat(s)"
    )

    assert len(first.threats) == 1
    assert len(second.threats) == 0

    assert (
        second.metadata["previous_commit"]
        == CURRENT_COMMIT
    )

    assert (
        second.metadata["current_commit"]
        == CURRENT_COMMIT
    )

    assert fake_connector.fetch_new_records_calls == 2


def test_all_threats_have_valid_identifier(
    tmp_path,
    sample_mitre_record: dict[str, Any],
) -> None:
    second_record = deepcopy(
        sample_mitre_record
    )

    second_record["cveMetadata"]["cveId"] = (
        "CVE-2026-9999"
    )

    source, _ = _build_source(
        tmp_path,
        [
            sample_mitre_record,
            second_record,
        ],
    )

    result = source.collect()

    print(
        "\n[MITRE SERVICE] "
        "Threat identifiers validation"
    )

    assert len(result.threats) == 2

    for threat in result.threats:
        print(threat.id)

        assert isinstance(threat.id, str)
        assert threat.id.startswith("CVE-")


def test_empty_fake_collection(
    tmp_path,
) -> None:
    """
    Verify collection when the fake connector returns no records.
    """

    source, _ = _build_source(
        tmp_path,
        [],
    )

    result = source.collect()

    assert isinstance(
        result,
        CollectionResult,
    )

    assert result.threats == []

    assert (
        result.metadata["records_collected"]
        == 0
    )


# ============================================================
# Integration tests: real GitHub / MITRE repository
# ============================================================


@pytest.mark.integration
def test_integration_download_and_parse_record(
    tmp_path,
) -> None:
    """
    Download one real CVE record and verify service parsing.
    """

    sync_file = (
        tmp_path
        / "mitre_sync_state.json"
    )

    source = MITREThreatSource(
        sync_state=MITRESyncState(
            filepath=str(sync_file)
        )
    )

    record = source.connector.download_cve_record(
        FILEPATH
    )

    threats = source.parse([record])

    assert len(threats) == 1

    threat = threats[0]

    print(
        "\n[MITRE SERVICE] "
        "Real CVE record parsed"
    )
    print(f"CVE ID: {threat.id}")

    assert isinstance(threat, Threat)
    assert threat.id == "CVE-2026-0964"
    assert threat.description != ""


@pytest.mark.integration
def test_integration_fetch_raw(
    tmp_path,
) -> None:
    """
    Verify real incremental fetching from GitHub.

    A temporary synchronization file protects the project's real
    synchronization state.
    """

    sync_file = (
        tmp_path
        / "mitre_sync_state.json"
    )

    source = MITREThreatSource(
        sync_state=MITRESyncState(
            filepath=str(sync_file)
        )
    )

    raw = source.fetch_raw()

    print(
        "\n[MITRE SERVICE] "
        "Real fetch_raw() execution"
    )
    print(
        "Previous commit : "
        f"{raw['previous_commit']}"
    )
    print(
        "Current commit  : "
        f"{raw['current_commit']}"
    )
    print(
        "Records fetched : "
        f"{len(raw['records'])}"
    )

    assert "previous_commit" in raw
    assert "current_commit" in raw
    assert "records" in raw

    assert raw["current_commit"] is not None
    assert isinstance(raw["records"], list)