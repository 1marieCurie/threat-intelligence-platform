from unittest.mock import Mock, patch
from uuid import uuid4

import pytest

from infrastructure.bootstrap.github_advisory_ingestion import (
    _get_optional_environment_variable,
    build_github_advisory_ingestion_job,
)


@patch(
    "infrastructure.bootstrap.github_advisory_ingestion."
    "RawIngestionJob"
)
@patch(
    "infrastructure.bootstrap.github_advisory_ingestion."
    "IngestionService"
)
@patch(
    "infrastructure.bootstrap.github_advisory_ingestion."
    "Sha256PayloadHasher"
)
@patch(
    "infrastructure.bootstrap.github_advisory_ingestion."
    "SqlAlchemyUnitOfWork"
)
@patch(
    "infrastructure.bootstrap.github_advisory_ingestion."
    "create_session_factory"
)
@patch(
    "infrastructure.bootstrap.github_advisory_ingestion."
    "create_ingestion_engine"
)
@patch(
    "infrastructure.bootstrap.github_advisory_ingestion."
    "GitHubAdvisoryIngestionConnector"
)
@patch(
    "infrastructure.bootstrap.github_advisory_ingestion."
    "GitHubAdvisoryConnector"
)
def test_build_job_composes_dependencies(
    github_connector_class: Mock,
    ingestion_connector_class: Mock,
    create_engine: Mock,
    create_session_factory: Mock,
    unit_of_work_class: Mock,
    payload_hasher_class: Mock,
    ingestion_service_class: Mock,
    job_class: Mock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_id = uuid4()

    monkeypatch.setenv(
        "GITHUB_TOKEN",
        "test-token",
    )

    github_connector = Mock()
    ingestion_connector = Mock()
    engine = Mock()
    session_factory = Mock()
    unit_of_work = Mock()
    payload_hasher = Mock()
    ingestion_service = Mock()
    expected_job = Mock()

    github_connector_class.return_value = github_connector
    ingestion_connector_class.return_value = (
        ingestion_connector
    )
    create_engine.return_value = engine
    create_session_factory.return_value = (
        session_factory
    )
    unit_of_work_class.return_value = unit_of_work
    payload_hasher_class.return_value = payload_hasher
    ingestion_service_class.return_value = (
        ingestion_service
    )
    job_class.return_value = expected_job

    result = build_github_advisory_ingestion_job(
        source_id=source_id,
    )

    github_connector_class.assert_called_once_with(
        token="test-token",
    )

    ingestion_connector_class.assert_called_once_with(
        connector=github_connector,
    )

    create_engine.assert_called_once_with()

    create_session_factory.assert_called_once_with(
        engine
    )

    unit_of_work_class.assert_called_once_with(
        session_factory=session_factory,
    )

    payload_hasher_class.assert_called_once_with()

    ingestion_service_class.assert_called_once_with(
        unit_of_work=unit_of_work,
        connector=ingestion_connector,
        payload_hasher=payload_hasher,
    )

    job_class.assert_called_once_with(
        ingestion_service=ingestion_service,
        source_id=source_id,
        source_code="GITHUB_ADVISORY",
    )

    assert result is expected_job


def test_build_job_rejects_invalid_source_id() -> None:
    with pytest.raises(
        TypeError,
        match="source_id must be a UUID",
    ):
        build_github_advisory_ingestion_job(
            source_id="invalid",  # type: ignore[arg-type]
        )


def test_get_environment_variable_returns_none_when_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv(
        "GITHUB_TOKEN",
        raising=False,
    )

    result = _get_optional_environment_variable(
        "GITHUB_TOKEN"
    )

    assert result is None


def test_get_environment_variable_returns_none_when_empty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        "GITHUB_TOKEN",
        "   ",
    )

    result = _get_optional_environment_variable(
        "GITHUB_TOKEN"
    )

    assert result is None


def test_get_environment_variable_trims_value(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        "GITHUB_TOKEN",
        "  secret-token  ",
    )

    result = _get_optional_environment_variable(
        "GITHUB_TOKEN"
    )

    assert result == "secret-token"

