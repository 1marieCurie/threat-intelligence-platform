from __future__ import annotations

from unittest.mock import Mock, patch

import pytest

from infrastructure.bootstrap.epss_synchronization import (
    DEFAULT_API_TIMEOUT_SECONDS,
    DEFAULT_MAX_CVE_IDS,
    EPSS_API_TIMEOUT_SECONDS_ENV,
    EPSS_SYNC_MAX_CVE_IDS_ENV,
    MAX_ALLOWED_CVE_IDS,
    MAX_API_TIMEOUT_SECONDS,
    build_epss_synchronization_job,
    build_epss_synchronization_service,
)


BOOTSTRAP_MODULE = (
    "infrastructure.bootstrap."
    "epss_synchronization"
)


def _remove_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    Supprime la configuration EPSS éventuellement
    chargée depuis le fichier .env.
    """
    for variable_name in (
        EPSS_API_TIMEOUT_SECONDS_ENV,
        EPSS_SYNC_MAX_CVE_IDS_ENV,
    ):
        monkeypatch.delenv(
            variable_name,
            raising=False,
        )


def test_build_job_composes_service(
) -> None:
    synchronization_service = Mock()
    expected_job = Mock()

    with (
        patch(
            f"{BOOTSTRAP_MODULE}."
            "build_epss_synchronization_service",
            return_value=synchronization_service,
        ) as build_service,
        patch(
            f"{BOOTSTRAP_MODULE}."
            "EPSSSynchronizationJob",
            return_value=expected_job,
        ) as job_class,
    ):
        result = (
            build_epss_synchronization_job()
        )

    build_service.assert_called_once_with()

    job_class.assert_called_once_with(
        synchronization_service=(
            synchronization_service
        ),
    )

    assert result is expected_job


def test_build_job_propagates_service_build_failure(
) -> None:
    expected_error = RuntimeError(
        "EPSS bootstrap failure"
    )

    with (
        patch(
            f"{BOOTSTRAP_MODULE}."
            "build_epss_synchronization_service",
            side_effect=expected_error,
        ),
        patch(
            f"{BOOTSTRAP_MODULE}."
            "EPSSSynchronizationJob",
        ) as job_class,
    ):
        with pytest.raises(
            RuntimeError,
            match="EPSS bootstrap failure",
        ) as raised_error:
            build_epss_synchronization_job()

    assert raised_error.value is expected_error
    job_class.assert_not_called()


def test_build_service_composes_defaults(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _remove_environment(
        monkeypatch
    )

    engine = Mock()
    session_factory = Mock()
    unit_of_work = Mock()
    provider = Mock()
    expected_service = Mock()

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
            "EPSSConnector",
            return_value=provider,
        ) as connector_class,
        patch(
            f"{BOOTSTRAP_MODULE}."
            "EPSSSynchronizationService",
            return_value=expected_service,
        ) as service_class,
    ):
        result = (
            build_epss_synchronization_service()
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
        provider=provider,
        unit_of_work=unit_of_work,
        max_cve_ids=DEFAULT_MAX_CVE_IDS,
    )

    assert result is expected_service


def test_build_service_uses_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _remove_environment(
        monkeypatch
    )

    monkeypatch.setenv(
        EPSS_API_TIMEOUT_SECONDS_ENV,
        " 15.5 ",
    )

    monkeypatch.setenv(
        EPSS_SYNC_MAX_CVE_IDS_ENV,
        " 1200 ",
    )

    engine = Mock()
    session_factory = Mock()
    unit_of_work = Mock()
    provider = Mock()
    expected_service = Mock()

    with (
        patch(
            f"{BOOTSTRAP_MODULE}."
            "create_ingestion_engine",
            return_value=engine,
        ),
        patch(
            f"{BOOTSTRAP_MODULE}."
            "create_session_factory",
            return_value=session_factory,
        ),
        patch(
            f"{BOOTSTRAP_MODULE}."
            "SqlAlchemyUnitOfWork",
            return_value=unit_of_work,
        ),
        patch(
            f"{BOOTSTRAP_MODULE}."
            "EPSSConnector",
            return_value=provider,
        ) as connector_class,
        patch(
            f"{BOOTSTRAP_MODULE}."
            "EPSSSynchronizationService",
            return_value=expected_service,
        ) as service_class,
    ):
        result = (
            build_epss_synchronization_service()
        )

    connector_class.assert_called_once_with(
        timeout=15.5,
    )

    service_class.assert_called_once_with(
        provider=provider,
        unit_of_work=unit_of_work,
        max_cve_ids=1200,
    )

    assert result is expected_service


@pytest.mark.parametrize(
    (
        "variable_name",
        "invalid_value",
        "expected_message",
    ),
    [
        (
            EPSS_API_TIMEOUT_SECONDS_ENV,
            "",
            (
                "EPSS_API_TIMEOUT_SECONDS "
                "must not be empty"
            ),
        ),
        (
            EPSS_API_TIMEOUT_SECONDS_ENV,
            "invalid",
            (
                "EPSS_API_TIMEOUT_SECONDS "
                "must be a number"
            ),
        ),
        (
            EPSS_API_TIMEOUT_SECONDS_ENV,
            "nan",
            (
                "EPSS_API_TIMEOUT_SECONDS "
                "must be finite"
            ),
        ),
        (
            EPSS_API_TIMEOUT_SECONDS_ENV,
            "inf",
            (
                "EPSS_API_TIMEOUT_SECONDS "
                "must be finite"
            ),
        ),
        (
            EPSS_API_TIMEOUT_SECONDS_ENV,
            "-inf",
            (
                "EPSS_API_TIMEOUT_SECONDS "
                "must be finite"
            ),
        ),
        (
            EPSS_API_TIMEOUT_SECONDS_ENV,
            "0",
            (
                "EPSS_API_TIMEOUT_SECONDS "
                "must be greater than zero"
            ),
        ),
        (
            EPSS_API_TIMEOUT_SECONDS_ENV,
            "-1",
            (
                "EPSS_API_TIMEOUT_SECONDS "
                "must be greater than zero"
            ),
        ),
        (
            EPSS_SYNC_MAX_CVE_IDS_ENV,
            "",
            (
                "EPSS_SYNC_MAX_CVE_IDS "
                "must not be empty"
            ),
        ),
        (
            EPSS_SYNC_MAX_CVE_IDS_ENV,
            "invalid",
            (
                "EPSS_SYNC_MAX_CVE_IDS "
                "must be an integer"
            ),
        ),
        (
            EPSS_SYNC_MAX_CVE_IDS_ENV,
            "1.5",
            (
                "EPSS_SYNC_MAX_CVE_IDS "
                "must be an integer"
            ),
        ),
        (
            EPSS_SYNC_MAX_CVE_IDS_ENV,
            "0",
            (
                "EPSS_SYNC_MAX_CVE_IDS "
                "must be greater than zero"
            ),
        ),
        (
            EPSS_SYNC_MAX_CVE_IDS_ENV,
            "-1",
            (
                "EPSS_SYNC_MAX_CVE_IDS "
                "must be greater than zero"
            ),
        ),
    ],
)
def test_build_service_rejects_invalid_environment(
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
            build_epss_synchronization_service()

    create_engine.assert_not_called()


@pytest.mark.parametrize(
    (
        "variable_name",
        "oversized_value",
        "expected_message",
    ),
    [
        (
            EPSS_API_TIMEOUT_SECONDS_ENV,
            str(
                MAX_API_TIMEOUT_SECONDS
                + 0.1
            ),
            (
                "EPSS_API_TIMEOUT_SECONDS "
                "must not exceed "
                f"{MAX_API_TIMEOUT_SECONDS:g}"
            ),
        ),
        (
            EPSS_SYNC_MAX_CVE_IDS_ENV,
            str(
                MAX_ALLOWED_CVE_IDS
                + 1
            ),
            (
                "EPSS_SYNC_MAX_CVE_IDS "
                "must not exceed "
                f"{MAX_ALLOWED_CVE_IDS}"
            ),
        ),
    ],
)
def test_build_service_rejects_oversized_configuration(
    variable_name: str,
    oversized_value: str,
    expected_message: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _remove_environment(
        monkeypatch
    )

    monkeypatch.setenv(
        variable_name,
        oversized_value,
    )

    with patch(
        f"{BOOTSTRAP_MODULE}."
        "create_ingestion_engine"
    ) as create_engine:
        with pytest.raises(
            RuntimeError,
            match=expected_message,
        ):
            build_epss_synchronization_service()

    create_engine.assert_not_called()