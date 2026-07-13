from pathlib import Path

import pytest

from infrastructure.adapters.outbound.phishtank_connector import (
    PhishTankConnector,
)


@pytest.mark.integration
def test_integration_get_real_phishtank_metadata(
    tmp_path: Path,
) -> None:
    """
    Real integration test.

    It performs only a HEAD request and does not download
    the complete PhishTank dump.
    """

    connector = PhishTankConnector(
        storage_directory=(
            tmp_path / "phishtank"
        ),
        user_agent=(
            "threat-intelligence-engine/"
            "integration-test"
        ),
        timeout=30.0,
    )

    metadata = connector.get_remote_metadata()

    assert isinstance(metadata, dict)

    assert set(metadata) == {
        "etag",
        "last_modified",
        "content_length",
    }

    assert (
        metadata["etag"] is not None
        or metadata["last_modified"] is not None
    )

    if metadata["content_length"] is not None:
        assert metadata["content_length"] > 0

@pytest.mark.integration
def test_integration_download_and_read_real_snapshot(
    tmp_path: Path,
) -> None:
    """
    Downloads the real compressed PhishTank snapshot.

    This test should be executed manually because public
    downloads may be rate-limited.
    """

    connector = PhishTankConnector(
        storage_directory=(
            tmp_path / "phishtank"
        ),
        user_agent=(
            "threat-intelligence-engine/"
            "integration-test"
        ),
        timeout=60.0,
    )

    records = connector.fetch_raw(
        force_download=True,
        limit=3,
    )

    assert len(records) == 3

    for record in records:
        assert isinstance(record, dict)
        assert "phish_id" in record
        assert "url" in record
        assert "verified" in record
        assert "online" in record

    assert connector.dump_path.exists()
    assert connector.dump_path.stat().st_size > 0

    state = connector.get_local_state()

    assert state["source"] == "PHISHTANK"
    assert state["downloaded"] is True
    assert state["used_local_snapshot"] is False
    assert state["dump_path"] == str(
        connector.dump_path
    )