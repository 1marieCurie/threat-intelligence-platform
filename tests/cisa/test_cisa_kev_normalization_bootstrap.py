from __future__ import annotations

from datetime import timedelta
from unittest.mock import Mock, patch
from uuid import uuid4

import pytest

from infrastructure.bootstrap.cisa_kev_normalization import (
    CISA_KEV_SOURCE_CODE,
    CISA_NORMALIZATION_BATCH_SIZE_ENV,
    CISA_NORMALIZATION_LEASE_TIMEOUT_SECONDS_ENV,
    CISA_NORMALIZATION_MAX_ATTEMPTS_ENV,
    DEFAULT_BATCH_SIZE,
    DEFAULT_LEASE_TIMEOUT_SECONDS,
    DEFAULT_MAX_ATTEMPTS,
    build_cisa_kev_normalization_job,
)


BOOTSTRAP_MODULE = (
    "infrastructure.bootstrap."
    "cisa_kev_normalization"
)


def _remove_normalization_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv(
        CISA_NORMALIZATION_BATCH_SIZE_ENV,
        raising=False,
    )
    monkeypatch.delenv(
        CISA_NORMALIZATION_LEASE_TIMEOUT_SECONDS_ENV,
        raising=False,
    )
    monkeypatch.delenv(
        CISA_NORMALIZATION_MAX_ATTEMPTS_ENV,
        raising=False,
    )


@patch(
    f"{BOOTSTRAP_MODULE}."
    "CisaKevNormalizationJob"
)
@patch(
    f"{BOOTSTRAP_MODULE}."
    "CisaKevNormalizationService"
)
@patch(
    f"{BOOTSTRAP_MODULE}."
    "CisaKevNormalizer"
)
@patch(
    f"{BOOTSTRAP_MODULE}."
    "SqlAlchemyUnitOfWork"
)
@patch(
    f"{BOOTSTRAP_MODULE}."
    "create_session_factory"
)
@patch(
    f"{BOOTSTRAP_MODULE}."
    "create_ingestion_engine"
)
def test_build_job_composes_dependencies_with_defaults(
    create_engine: Mock,
    create_session_factory: Mock,
    unit_of_work_class: Mock,
    normalizer_class: Mock,
    normalization_service_class: Mock,
    job_class: Mock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _remove_normalization_environment(
        monkeypatch
    )

    source_id = uuid4()

    engine = Mock()
    session_factory = Mock()
    unit_of_work = Mock()
    normalizer = Mock()
    normalization_service = Mock()
    expected_job = Mock()

    create_engine.return_value = engine
    create_session_factory.return_value = (
        session_factory
    )
    unit_of_work_class.return_value = (
        unit_of_work
    )
    normalizer_class.return_value = normalizer
    normalization_service_class.return_value = (
        normalization_service
    )
    job_class.return_value = expected_job

    result = build_cisa_kev_normalization_job(
        source_id=source_id,
    )

    create_engine.assert_called_once_with()

    create_session_factory.assert_called_once_with(
        engine
    )

    unit_of_work_class.assert_called_once_with(
        session_factory=session_factory,
    )

    normalizer_class.assert_called_once_with()

    normalization_service_class.assert_called_once_with(
        unit_of_work=unit_of_work,
        normalizer=normalizer,
        lease_timeout=timedelta(
            seconds=DEFAULT_LEASE_TIMEOUT_SECONDS
        ),
        max_attempts=DEFAULT_MAX_ATTEMPTS,
    )

    job_class.assert_called_once_with(
        normalization_service=(
            normalization_service
        ),
        source_id=source_id,
        source_code=CISA_KEV_SOURCE_CODE,
        batch_size=DEFAULT_BATCH_SIZE,
    )

    assert result is expected_job


@patch(
    f"{BOOTSTRAP_MODULE}."
    "CisaKevNormalizationJob"
)
@patch(
    f"{BOOTSTRAP_MODULE}."
    "CisaKevNormalizationService"
)
@patch(
    f"{BOOTSTRAP_MODULE}."
    "CisaKevNormalizer"
)
@patch(
    f"{BOOTSTRAP_MODULE}."
    "SqlAlchemyUnitOfWork"
)
@patch(
    f"{BOOTSTRAP_MODULE}."
    "create_session_factory"
)
@patch(
    f"{BOOTSTRAP_MODULE}."
    "create_ingestion_engine"
)
def test_build_job_uses_environment_configuration(
    create_engine: Mock,
    create_session_factory: Mock,
    unit_of_work_class: Mock,
    normalizer_class: Mock,
    normalization_service_class: Mock,
    job_class: Mock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        CISA_NORMALIZATION_BATCH_SIZE_ENV,
        "25",
    )
    monkeypatch.setenv(
        CISA_NORMALIZATION_LEASE_TIMEOUT_SECONDS_ENV,
        "120",
    )
    monkeypatch.setenv(
        CISA_NORMALIZATION_MAX_ATTEMPTS_ENV,
        "5",
    )

    source_id = uuid4()

    engine = Mock()
    session_factory = Mock()
    unit_of_work = Mock()
    normalizer = Mock()
    normalization_service = Mock()
    expected_job = Mock()

    create_engine.return_value = engine
    create_session_factory.return_value = (
        session_factory
    )
    unit_of_work_class.return_value = (
        unit_of_work
    )
    normalizer_class.return_value = normalizer
    normalization_service_class.return_value = (
        normalization_service
    )
    job_class.return_value = expected_job

    result = build_cisa_kev_normalization_job(
        source_id=source_id,
    )

    normalization_service_class.assert_called_once_with(
        unit_of_work=unit_of_work,
        normalizer=normalizer,
        lease_timeout=timedelta(
            seconds=120
        ),
        max_attempts=5,
    )

    job_class.assert_called_once_with(
        normalization_service=(
            normalization_service
        ),
        source_id=source_id,
        source_code=CISA_KEV_SOURCE_CODE,
        batch_size=25,
    )

    assert result is expected_job


def test_build_job_rejects_invalid_source_id() -> None:
    with pytest.raises(
        TypeError,
        match="source_id must be a UUID",
    ):
        build_cisa_kev_normalization_job(
            source_id="invalid",  # type: ignore[arg-type]
        )


@pytest.mark.parametrize(
    (
        "variable_name",
        "invalid_value",
        "expected_message",
    ),
    [
        (
            CISA_NORMALIZATION_BATCH_SIZE_ENV,
            "",
            (
                "CISA_NORMALIZATION_BATCH_SIZE "
                "must not be empty"
            ),
        ),
        (
            CISA_NORMALIZATION_BATCH_SIZE_ENV,
            "invalid",
            (
                "CISA_NORMALIZATION_BATCH_SIZE "
                "must be an integer"
            ),
        ),
        (
            CISA_NORMALIZATION_BATCH_SIZE_ENV,
            "0",
            (
                "CISA_NORMALIZATION_BATCH_SIZE "
                "must be greater than zero"
            ),
        ),
        (
            CISA_NORMALIZATION_LEASE_TIMEOUT_SECONDS_ENV,
            "-1",
            (
                "CISA_NORMALIZATION_LEASE_TIMEOUT_SECONDS "
                "must be greater than zero"
            ),
        ),
        (
            CISA_NORMALIZATION_MAX_ATTEMPTS_ENV,
            "1.5",
            (
                "CISA_NORMALIZATION_MAX_ATTEMPTS "
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
    _remove_normalization_environment(
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
            build_cisa_kev_normalization_job(
                source_id=uuid4(),
            )

    create_engine.assert_not_called()


@pytest.mark.parametrize(
    (
        "variable_name",
        "environment_value",
        "expected_value",
    ),
    [
        (
            CISA_NORMALIZATION_BATCH_SIZE_ENV,
            " 50 ",
            50,
        ),
        (
            CISA_NORMALIZATION_LEASE_TIMEOUT_SECONDS_ENV,
            " 300 ",
            300,
        ),
        (
            CISA_NORMALIZATION_MAX_ATTEMPTS_ENV,
            " 4 ",
            4,
        ),
    ],
)
def test_environment_values_are_trimmed(
    variable_name: str,
    environment_value: str,
    expected_value: int,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _remove_normalization_environment(
        monkeypatch
    )

    monkeypatch.setenv(
        variable_name,
        environment_value,
    )

    with (
        patch(
            f"{BOOTSTRAP_MODULE}."
            "create_ingestion_engine"
        ) as create_engine,
        patch(
            f"{BOOTSTRAP_MODULE}."
            "create_session_factory"
        ) as create_session_factory,
        patch(
            f"{BOOTSTRAP_MODULE}."
            "SqlAlchemyUnitOfWork"
        ),
        patch(
            f"{BOOTSTRAP_MODULE}."
            "CisaKevNormalizer"
        ),
        patch(
            f"{BOOTSTRAP_MODULE}."
            "CisaKevNormalizationService"
        ) as service_class,
        patch(
            f"{BOOTSTRAP_MODULE}."
            "CisaKevNormalizationJob"
        ) as job_class,
    ):
        create_session_factory.return_value = Mock()
        create_engine.return_value = Mock()

        build_cisa_kev_normalization_job(
            source_id=uuid4(),
        )

    if (
        variable_name
        == CISA_NORMALIZATION_BATCH_SIZE_ENV
    ):
        assert (
            job_class.call_args.kwargs["batch_size"]
            == expected_value
        )
    elif (
        variable_name
        == CISA_NORMALIZATION_LEASE_TIMEOUT_SECONDS_ENV
    ):
        assert (
            service_class.call_args.kwargs[
                "lease_timeout"
            ]
            == timedelta(
                seconds=expected_value
            )
        )
    else:
        assert (
            service_class.call_args.kwargs[
                "max_attempts"
            ]
            == expected_value
        )