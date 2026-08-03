from __future__ import annotations

import os
from unittest.mock import Mock, patch
from uuid import uuid4

import pytest

from infrastructure.adapters.outbound.urlhaus_connector import (
    URLhausAuthenticationError,
)
from infrastructure.bootstrap.urlhaus_ingestion import (
    DEFAULT_BASE_URL,
    DEFAULT_BATCH_SIZE,
    DEFAULT_TIMEOUT,
    URLHAUS_SOURCE_CODE,
    build_urlhaus_ingestion_job,
)


def test_build_job_composes_dependencies(
) -> None:
    source_id = uuid4()

    with (
        patch(
            "infrastructure.bootstrap."
            "urlhaus_ingestion.URLhausConnector"
        ) as connector_class,
        patch(
            "infrastructure.bootstrap."
            "urlhaus_ingestion."
            "URLhausIngestionConnector"
        ) as ingestion_connector_class,
        patch(
            "infrastructure.bootstrap."
            "urlhaus_ingestion."
            "create_ingestion_engine"
        ) as create_engine,
        patch(
            "infrastructure.bootstrap."
            "urlhaus_ingestion."
            "create_session_factory"
        ) as create_session_factory,
        patch(
            "infrastructure.bootstrap."
            "urlhaus_ingestion."
            "SqlAlchemyUnitOfWork"
        ) as unit_of_work_class,
        patch(
            "infrastructure.bootstrap."
            "urlhaus_ingestion."
            "Sha256PayloadHasher"
        ) as payload_hasher_class,
        patch(
            "infrastructure.bootstrap."
            "urlhaus_ingestion."
            "IngestionService"
        ) as ingestion_service_class,
        patch(
            "infrastructure.bootstrap."
            "urlhaus_ingestion."
            "RawIngestionJob"
        ) as job_class,
    ):
        connector = Mock()
        ingestion_connector = Mock()
        engine = Mock()
        session_factory = Mock()
        unit_of_work = Mock()
        payload_hasher = Mock()
        ingestion_service = Mock()
        expected_job = Mock()

        connector_class.return_value = (
            connector
        )

        ingestion_connector_class.return_value = (
            ingestion_connector
        )

        create_engine.return_value = (
            engine
        )

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

        job_class.return_value = (
            expected_job
        )

        with patch.dict(
            os.environ,
            {
                "URLHAUS_AUTH_KEY": (
                    " test-auth-key "
                ),
            },
            clear=False,
        ):
            result = (
                build_urlhaus_ingestion_job(
                    source_id=source_id,
                    limit=100,
                    batch_size=250,
                    timeout=12.5,
                    base_url=(
                        "https://example.test/v1"
                    ),
                )
            )

        connector_class.assert_called_once_with(
            auth_key="test-auth-key",
            timeout=12.5,
            base_url=(
                "https://example.test/v1"
            ),
        )

        ingestion_connector_class.assert_called_once_with(
            connector=connector,
            limit=100,
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
            ingestion_service=ingestion_service,
            source_id=source_id,
            source_code=URLHAUS_SOURCE_CODE,
        )

        assert result is expected_job


def test_build_job_uses_safe_defaults(
) -> None:
    source_id = uuid4()

    with (
        patch(
            "infrastructure.bootstrap."
            "urlhaus_ingestion.URLhausConnector"
        ) as connector_class,
        patch(
            "infrastructure.bootstrap."
            "urlhaus_ingestion."
            "URLhausIngestionConnector"
        ) as ingestion_connector_class,
        patch(
            "infrastructure.bootstrap."
            "urlhaus_ingestion."
            "create_ingestion_engine"
        ) as create_engine,
        patch(
            "infrastructure.bootstrap."
            "urlhaus_ingestion."
            "create_session_factory"
        ) as create_session_factory,
        patch(
            "infrastructure.bootstrap."
            "urlhaus_ingestion."
            "SqlAlchemyUnitOfWork"
        ) as unit_of_work_class,
        patch(
            "infrastructure.bootstrap."
            "urlhaus_ingestion."
            "Sha256PayloadHasher"
        ) as payload_hasher_class,
        patch(
            "infrastructure.bootstrap."
            "urlhaus_ingestion."
            "IngestionService"
        ) as ingestion_service_class,
        patch(
            "infrastructure.bootstrap."
            "urlhaus_ingestion."
            "RawIngestionJob"
        ) as job_class,
    ):
        connector = Mock()
        ingestion_connector = Mock()
        engine = Mock()
        session_factory = Mock()
        unit_of_work = Mock()
        payload_hasher = Mock()
        ingestion_service = Mock()
        expected_job = Mock()

        connector_class.return_value = (
            connector
        )

        ingestion_connector_class.return_value = (
            ingestion_connector
        )

        create_engine.return_value = (
            engine
        )

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

        job_class.return_value = (
            expected_job
        )

        with patch.dict(
            os.environ,
            {
                "URLHAUS_AUTH_KEY": (
                    "test-auth-key"
                ),
            },
            clear=False,
        ):
            result = (
                build_urlhaus_ingestion_job(
                    source_id=source_id,
                )
            )

        connector_class.assert_called_once_with(
            auth_key="test-auth-key",
            timeout=DEFAULT_TIMEOUT,
            base_url=DEFAULT_BASE_URL,
        )

        ingestion_connector_class.assert_called_once_with(
            connector=connector,
            limit=None,
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
        build_urlhaus_ingestion_job(
            source_id="invalid",  # type: ignore[arg-type]
        )


def test_build_job_rejects_missing_auth_key(
) -> None:
    with patch.dict(
        os.environ,
        {},
        clear=False,
    ):
        os.environ.pop(
            "URLHAUS_AUTH_KEY",
            None,
        )

        with pytest.raises(
            URLhausAuthenticationError,
            match="Auth-Key is required",
        ):
            build_urlhaus_ingestion_job(
                source_id=uuid4(),
            )


@pytest.mark.parametrize(
    "auth_key",
    [
        "",
        "   ",
    ],
)
def test_build_job_rejects_empty_auth_key(
    auth_key: str,
) -> None:
    with patch.dict(
        os.environ,
        {
            "URLHAUS_AUTH_KEY": (
                auth_key
            ),
        },
        clear=False,
    ):
        with pytest.raises(
            URLhausAuthenticationError,
            match="must not be empty",
        ):
            build_urlhaus_ingestion_job(
                source_id=uuid4(),
            )