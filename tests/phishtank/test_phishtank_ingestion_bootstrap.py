from __future__ import annotations

import os
from unittest.mock import Mock, patch
from uuid import uuid4

import pytest

from infrastructure.bootstrap.phishtank_ingestion import (
    DEFAULT_BATCH_SIZE,
    DEFAULT_STORAGE_DIRECTORY,
    PHISHTANK_SOURCE_CODE,
    build_phishtank_ingestion_job,
)


@patch(
    "infrastructure.bootstrap."
    "phishtank_ingestion.RawIngestionJob"
)
@patch(
    "infrastructure.bootstrap."
    "phishtank_ingestion.IngestionService"
)
@patch(
    "infrastructure.bootstrap."
    "phishtank_ingestion.Sha256PayloadHasher"
)
@patch(
    "infrastructure.bootstrap."
    "phishtank_ingestion.SqlAlchemyUnitOfWork"
)
@patch(
    "infrastructure.bootstrap."
    "phishtank_ingestion.create_session_factory"
)
@patch(
    "infrastructure.bootstrap."
    "phishtank_ingestion.create_ingestion_engine"
)
@patch(
    "infrastructure.bootstrap."
    "phishtank_ingestion.PhishTankIngestionConnector"
)
@patch(
    "infrastructure.bootstrap."
    "phishtank_ingestion.PhishTankConnector"
)
def test_build_job_composes_dependencies(
    phishtank_connector_class: Mock,
    ingestion_connector_class: Mock,
    create_engine: Mock,
    create_session_factory: Mock,
    unit_of_work_class: Mock,
    payload_hasher_class: Mock,
    ingestion_service_class: Mock,
    job_class: Mock,
) -> None:
    source_id = uuid4()

    phishtank_connector = Mock()
    ingestion_connector = Mock()
    engine = Mock()
    session_factory = Mock()
    unit_of_work = Mock()
    payload_hasher = Mock()
    ingestion_service = Mock()
    expected_job = Mock()

    phishtank_connector_class.return_value = (
        phishtank_connector
    )

    ingestion_connector_class.return_value = (
        ingestion_connector
    )

    create_engine.return_value = engine

    create_session_factory.return_value = (
        session_factory
    )

    unit_of_work_class.return_value = (
        unit_of_work
    )

    payload_hasher_class.return_value = (
        payload_hasher
    )

    ingestion_service_class.return_value = (
        ingestion_service
    )

    job_class.return_value = expected_job

    with patch.dict(
        os.environ,
        {
            "PHISHTANK_APP_KEY": (
                " test-app-key "
            ),
            "PHISHTANK_STORAGE_DIRECTORY": (
                " test-data/phishtank "
            ),
        },
        clear=False,
    ):
        result = (
            build_phishtank_ingestion_job(
                source_id=source_id,
                limit=100,
                force_download=True,
                batch_size=250,
            )
        )

    phishtank_connector_class.assert_called_once_with(
        storage_directory=(
            "test-data/phishtank"
        ),
        app_key="test-app-key",
    )

    ingestion_connector_class.assert_called_once_with(
        connector=phishtank_connector,
        limit=100,
        force_download=True,
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
        batch_size=250,
    )

    job_class.assert_called_once_with(
        ingestion_service=(
            ingestion_service
        ),
        source_id=source_id,
        source_code=(
            PHISHTANK_SOURCE_CODE
        ),
    )

    assert result is expected_job


@patch(
    "infrastructure.bootstrap."
    "phishtank_ingestion.RawIngestionJob"
)
@patch(
    "infrastructure.bootstrap."
    "phishtank_ingestion.IngestionService"
)
@patch(
    "infrastructure.bootstrap."
    "phishtank_ingestion.Sha256PayloadHasher"
)
@patch(
    "infrastructure.bootstrap."
    "phishtank_ingestion.SqlAlchemyUnitOfWork"
)
@patch(
    "infrastructure.bootstrap."
    "phishtank_ingestion.create_session_factory"
)
@patch(
    "infrastructure.bootstrap."
    "phishtank_ingestion.create_ingestion_engine"
)
@patch(
    "infrastructure.bootstrap."
    "phishtank_ingestion.PhishTankIngestionConnector"
)
@patch(
    "infrastructure.bootstrap."
    "phishtank_ingestion.PhishTankConnector"
)
def test_build_job_uses_safe_defaults(
    phishtank_connector_class: Mock,
    ingestion_connector_class: Mock,
    create_engine: Mock,
    create_session_factory: Mock,
    unit_of_work_class: Mock,
    payload_hasher_class: Mock,
    ingestion_service_class: Mock,
    job_class: Mock,
) -> None:
    source_id = uuid4()

    phishtank_connector = Mock()
    ingestion_connector = Mock()
    engine = Mock()
    session_factory = Mock()
    unit_of_work = Mock()
    payload_hasher = Mock()
    ingestion_service = Mock()
    expected_job = Mock()

    phishtank_connector_class.return_value = (
        phishtank_connector
    )

    ingestion_connector_class.return_value = (
        ingestion_connector
    )

    create_engine.return_value = engine

    create_session_factory.return_value = (
        session_factory
    )

    unit_of_work_class.return_value = (
        unit_of_work
    )

    payload_hasher_class.return_value = (
        payload_hasher
    )

    ingestion_service_class.return_value = (
        ingestion_service
    )

    job_class.return_value = expected_job

    with patch.dict(
        os.environ,
        {},
        clear=False,
    ):
        os.environ.pop(
            "PHISHTANK_APP_KEY",
            None,
        )

        os.environ.pop(
            "PHISHTANK_STORAGE_DIRECTORY",
            None,
        )

        result = (
            build_phishtank_ingestion_job(
                source_id=source_id,
            )
        )

    phishtank_connector_class.assert_called_once_with(
        storage_directory=(
            DEFAULT_STORAGE_DIRECTORY
        ),
        app_key=None,
    )

    ingestion_connector_class.assert_called_once_with(
        connector=phishtank_connector,
        limit=None,
        force_download=False,
    )

    ingestion_service_class.assert_called_once_with(
        unit_of_work=unit_of_work,
        connector=ingestion_connector,
        payload_hasher=payload_hasher,
        batch_size=DEFAULT_BATCH_SIZE,
    )

    assert result is expected_job


def test_build_job_rejects_invalid_source_id(
) -> None:
    with pytest.raises(
        TypeError,
        match="source_id must be a UUID",
    ):
        build_phishtank_ingestion_job(
            source_id="invalid",  # type: ignore[arg-type]
        )