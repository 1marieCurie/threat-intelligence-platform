from __future__ import annotations

from unittest.mock import Mock, patch
from uuid import uuid4

import pytest

from infrastructure.bootstrap.cisa_kev_ingestion import (
    CISA_KEV_SOURCE_CODE,
    build_cisa_kev_ingestion_job,
)


@patch(
    "infrastructure.bootstrap.cisa_kev_ingestion."
    "RawIngestionJob"
)
@patch(
    "infrastructure.bootstrap.cisa_kev_ingestion."
    "IngestionService"
)
@patch(
    "infrastructure.bootstrap.cisa_kev_ingestion."
    "Sha256PayloadHasher"
)
@patch(
    "infrastructure.bootstrap.cisa_kev_ingestion."
    "SqlAlchemyUnitOfWork"
)
@patch(
    "infrastructure.bootstrap.cisa_kev_ingestion."
    "create_session_factory"
)
@patch(
    "infrastructure.bootstrap.cisa_kev_ingestion."
    "create_ingestion_engine"
)
@patch(
    "infrastructure.bootstrap.cisa_kev_ingestion."
    "CisaKevIngestionConnector"
)
@patch(
    "infrastructure.bootstrap.cisa_kev_ingestion."
    "CISAConnector"
)
def test_build_job_composes_dependencies(
    cisa_connector_class: Mock,
    ingestion_connector_class: Mock,
    create_engine: Mock,
    create_session_factory: Mock,
    unit_of_work_class: Mock,
    payload_hasher_class: Mock,
    ingestion_service_class: Mock,
    job_class: Mock,
) -> None:
    source_id = uuid4()

    cisa_connector = Mock()
    ingestion_connector = Mock()
    engine = Mock()
    session_factory = Mock()
    unit_of_work = Mock()
    payload_hasher = Mock()
    ingestion_service = Mock()
    expected_job = Mock()

    cisa_connector_class.return_value = (
        cisa_connector
    )
    ingestion_connector_class.return_value = (
        ingestion_connector
    )
    create_engine.return_value = engine
    create_session_factory.return_value = (
        session_factory
    )
    unit_of_work_class.return_value = unit_of_work
    payload_hasher_class.return_value = (
        payload_hasher
    )
    ingestion_service_class.return_value = (
        ingestion_service
    )
    job_class.return_value = expected_job

    result = build_cisa_kev_ingestion_job(
        source_id=source_id,
    )

    cisa_connector_class.assert_called_once_with()

    ingestion_connector_class.assert_called_once_with(
        connector=cisa_connector,
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
        source_code=CISA_KEV_SOURCE_CODE,
    )

    assert result is expected_job


def test_build_job_rejects_invalid_source_id() -> None:
    with pytest.raises(
        TypeError,
        match="source_id must be a UUID",
    ):
        build_cisa_kev_ingestion_job(
            source_id="invalid",  # type: ignore[arg-type]
        )