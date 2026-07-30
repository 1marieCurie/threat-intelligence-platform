from __future__ import annotations

from unittest.mock import Mock, patch

import pytest

from infrastructure.bootstrap.cwe_catalog_sync import (
    CWE_API_TIMEOUT_SECONDS_ENV,
    CWE_CATALOG_SYNC_BATCH_SIZE_ENV,
    CWE_CATALOG_SYNC_MAX_IDS_ENV,
    DEFAULT_API_TIMEOUT_SECONDS,
    DEFAULT_BATCH_SIZE,
    DEFAULT_MAX_CWE_IDS,
    build_cwe_catalog_sync_job,
)


BOOTSTRAP_MODULE = (
    "infrastructure.bootstrap."
    "cwe_catalog_sync"
)


def _remove_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for variable_name in (
        CWE_CATALOG_SYNC_BATCH_SIZE_ENV,
        CWE_CATALOG_SYNC_MAX_IDS_ENV,
        CWE_API_TIMEOUT_SECONDS_ENV,
    ):
        monkeypatch.delenv(
            variable_name,
            raising=False,
        )


def test_build_job_composes_defaults(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _remove_environment(
        monkeypatch
    )

    engine = Mock()
    session_factory = Mock()
    unit_of_work = Mock()
    client = Mock()
    service = Mock()
    expected_job = Mock()

    with (
        patch(
            f"{BOOTSTRAP_MODULE}."
            "create_ingestion_engine",
            return_value=engine,
        ) as create_engine,
        patch(
            f"{BOOTSTRAP_MODULE}."
            "create_session_factory",
            return_value=session_factory,
        ) as create_factory,
        patch(
            f"{BOOTSTRAP_MODULE}."
            "SqlAlchemyUnitOfWork",
            return_value=unit_of_work,
        ) as unit_of_work_class,
        patch(
            f"{BOOTSTRAP_MODULE}."
            "CWEConnector",
            return_value=client,
        ) as connector_class,
        patch(
            f"{BOOTSTRAP_MODULE}."
            "CWECatalogSyncService",
            return_value=service,
        ) as service_class,
        patch(
            f"{BOOTSTRAP_MODULE}."
            "CWECatalogSyncJob",
            return_value=expected_job,
        ) as job_class,
    ):
        result = (
            build_cwe_catalog_sync_job()
        )

    create_engine.assert_called_once_with()

    create_factory.assert_called_once_with(
        engine
    )

    unit_of_work_class.assert_called_once_with(
        session_factory=session_factory,
    )

    connector_class.assert_called_once_with(
        timeout=DEFAULT_API_TIMEOUT_SECONDS,
    )

    service_class.assert_called_once_with(
        client=client,
        unit_of_work=unit_of_work,
        batch_size=DEFAULT_BATCH_SIZE,
        max_cwe_ids=DEFAULT_MAX_CWE_IDS,
    )

    job_class.assert_called_once_with(
        sync_service=service,
    )

    assert result is expected_job


def test_build_job_uses_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        CWE_CATALOG_SYNC_BATCH_SIZE_ENV,
        " 25 ",
    )

    monkeypatch.setenv(
        CWE_CATALOG_SYNC_MAX_IDS_ENV,
        " 1200 ",
    )

    monkeypatch.setenv(
        CWE_API_TIMEOUT_SECONDS_ENV,
        " 10 ",
    )

    with (
        patch(
            f"{BOOTSTRAP_MODULE}."
            "create_ingestion_engine",
            return_value=Mock(),
        ),
        patch(
            f"{BOOTSTRAP_MODULE}."
            "create_session_factory",
            return_value=Mock(),
        ),
        patch(
            f"{BOOTSTRAP_MODULE}."
            "SqlAlchemyUnitOfWork",
            return_value=Mock(),
        ),
        patch(
            f"{BOOTSTRAP_MODULE}."
            "CWEConnector",
            return_value=Mock(),
        ) as connector_class,
        patch(
            f"{BOOTSTRAP_MODULE}."
            "CWECatalogSyncService",
            return_value=Mock(),
        ) as service_class,
        patch(
            f"{BOOTSTRAP_MODULE}."
            "CWECatalogSyncJob",
            return_value=Mock(),
        ),
    ):
        build_cwe_catalog_sync_job()

    connector_class.assert_called_once_with(
        timeout=10,
    )

    assert (
        service_class.call_args.kwargs[
            "batch_size"
        ]
        == 25
    )

    assert (
        service_class.call_args.kwargs[
            "max_cwe_ids"
        ]
        == 1200
    )


@pytest.mark.parametrize(
    (
        "variable_name",
        "invalid_value",
        "expected_message",
    ),
    [
        (
            CWE_CATALOG_SYNC_BATCH_SIZE_ENV,
            "",
            (
                "CWE_CATALOG_SYNC_BATCH_SIZE "
                "must not be empty"
            ),
        ),
        (
            CWE_CATALOG_SYNC_BATCH_SIZE_ENV,
            "invalid",
            (
                "CWE_CATALOG_SYNC_BATCH_SIZE "
                "must be an integer"
            ),
        ),
        (
            CWE_CATALOG_SYNC_MAX_IDS_ENV,
            "0",
            (
                "CWE_CATALOG_SYNC_MAX_IDS "
                "must be greater than zero"
            ),
        ),
        (
            CWE_CATALOG_SYNC_MAX_IDS_ENV,
            "-1",
            (
                "CWE_CATALOG_SYNC_MAX_IDS "
                "must be greater than zero"
            ),
        ),
        (
            CWE_API_TIMEOUT_SECONDS_ENV,
            "1.5",
            (
                "CWE_API_TIMEOUT_SECONDS "
                "must be an integer"
            ),
        ),
    ],
)
def test_build_job_rejects_invalid_environment(
    variable_name: str,
    invalid_value: str,
    expected_message: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _remove_environment(
        monkeypatch
    )

    monkeypatch.setenv(
        variable_name,
        invalid_value,
    )

    with patch(
        f"{BOOTSTRAP_MODULE}."
        "create_ingestion_engine"
    ) as create_engine:
        with pytest.raises(
            RuntimeError,
            match=expected_message,
        ):
            build_cwe_catalog_sync_job()

    create_engine.assert_not_called()


def test_build_job_rejects_oversized_batch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _remove_environment(
        monkeypatch
    )

    monkeypatch.setenv(
        CWE_CATALOG_SYNC_BATCH_SIZE_ENV,
        "51",
    )

    with patch(
        f"{BOOTSTRAP_MODULE}."
        "create_ingestion_engine"
    ) as create_engine:
        with pytest.raises(
            RuntimeError,
            match=(
                "CWE_CATALOG_SYNC_BATCH_SIZE "
                "must not exceed 50"
            ),
        ):
            build_cwe_catalog_sync_job()

    create_engine.assert_not_called()