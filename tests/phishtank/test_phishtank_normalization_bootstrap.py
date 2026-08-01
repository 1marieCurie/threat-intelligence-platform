from __future__ import annotations

from datetime import timedelta
from unittest.mock import (
    Mock,
    patch,
)
from uuid import uuid4

import pytest

from infrastructure.bootstrap.phishtank_normalization import (
    DEFAULT_BATCH_SIZE,
    DEFAULT_LEASE_TIMEOUT_SECONDS,
    DEFAULT_MAX_ATTEMPTS,
    PHISHTANK_NORMALIZATION_BATCH_SIZE_ENV,
    PHISHTANK_NORMALIZATION_LEASE_TIMEOUT_SECONDS_ENV,
    PHISHTANK_NORMALIZATION_MAX_ATTEMPTS_ENV,
    PHISHTANK_SOURCE_CODE,
    build_phishtank_normalization_job,
)


BOOTSTRAP_MODULE = (
    "infrastructure.bootstrap."
    "phishtank_normalization"
)


def _remove_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for variable_name in (
        PHISHTANK_NORMALIZATION_BATCH_SIZE_ENV,
        PHISHTANK_NORMALIZATION_LEASE_TIMEOUT_SECONDS_ENV,
        PHISHTANK_NORMALIZATION_MAX_ATTEMPTS_ENV,
    ):
        monkeypatch.delenv(
            variable_name,
            raising=False,
        )


@patch(
    f"{BOOTSTRAP_MODULE}."
    "PhishTankNormalizationJob"
)
@patch(
    f"{BOOTSTRAP_MODULE}."
    "PhishTankNormalizationService"
)
@patch(
    f"{BOOTSTRAP_MODULE}."
    "PhishTankNormalizer"
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
def test_build_job_composes_defaults(
    create_engine: Mock,
    create_session_factory: Mock,
    unit_of_work_class: Mock,
    normalizer_class: Mock,
    service_class: Mock,
    job_class: Mock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _remove_environment(
        monkeypatch
    )

    source_id = uuid4()

    engine = Mock()
    session_factory = Mock()
    unit_of_work = Mock()
    normalizer = Mock()
    service = Mock()
    expected_job = Mock()

    create_engine.return_value = engine

    create_session_factory.return_value = (
        session_factory
    )

    unit_of_work_class.return_value = (
        unit_of_work
    )

    normalizer_class.return_value = (
        normalizer
    )

    service_class.return_value = service
    job_class.return_value = expected_job

    result = (
        build_phishtank_normalization_job(
            source_id=source_id
        )
    )

    create_engine.assert_called_once_with()

    create_session_factory \
        .assert_called_once_with(
            engine
        )

    unit_of_work_class \
        .assert_called_once_with(
            session_factory=(
                session_factory
            ),
        )

    normalizer_class \
        .assert_called_once_with()

    service_class.assert_called_once_with(
        unit_of_work=unit_of_work,
        normalizer=normalizer,
        lease_timeout=timedelta(
            seconds=(
                DEFAULT_LEASE_TIMEOUT_SECONDS
            ),
        ),
        max_attempts=(
            DEFAULT_MAX_ATTEMPTS
        ),
    )

    job_class.assert_called_once_with(
        normalization_service=service,
        source_id=source_id,
        source_code=PHISHTANK_SOURCE_CODE,
        batch_size=DEFAULT_BATCH_SIZE,
    )

    assert result is expected_job


@patch(
    f"{BOOTSTRAP_MODULE}."
    "PhishTankNormalizationJob"
)
@patch(
    f"{BOOTSTRAP_MODULE}."
    "PhishTankNormalizationService"
)
@patch(
    f"{BOOTSTRAP_MODULE}."
    "PhishTankNormalizer"
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
def test_build_job_uses_environment(
    create_engine: Mock,
    create_session_factory: Mock,
    unit_of_work_class: Mock,
    normalizer_class: Mock,
    service_class: Mock,
    job_class: Mock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        PHISHTANK_NORMALIZATION_BATCH_SIZE_ENV,
        "25",
    )

    monkeypatch.setenv(
        PHISHTANK_NORMALIZATION_LEASE_TIMEOUT_SECONDS_ENV,
        "120",
    )

    monkeypatch.setenv(
        PHISHTANK_NORMALIZATION_MAX_ATTEMPTS_ENV,
        "5",
    )

    create_engine.return_value = Mock()

    create_session_factory.return_value = (
        Mock()
    )

    unit_of_work_class.return_value = (
        Mock()
    )

    normalizer_class.return_value = (
        Mock()
    )

    service_class.return_value = (
        Mock()
    )

    build_phishtank_normalization_job(
        source_id=uuid4()
    )

    assert (
        service_class
        .call_args
        .kwargs[
            "lease_timeout"
        ]
        == timedelta(
            seconds=120
        )
    )

    assert (
        service_class
        .call_args
        .kwargs[
            "max_attempts"
        ]
        == 5
    )

    assert (
        job_class
        .call_args
        .kwargs[
            "batch_size"
        ]
        == 25
    )


@pytest.mark.parametrize(
    (
        "variable_name",
        "invalid_value",
    ),
    [
        (
            PHISHTANK_NORMALIZATION_BATCH_SIZE_ENV,
            "",
        ),
        (
            PHISHTANK_NORMALIZATION_BATCH_SIZE_ENV,
            "invalid",
        ),
        (
            PHISHTANK_NORMALIZATION_BATCH_SIZE_ENV,
            "0",
        ),
        (
            PHISHTANK_NORMALIZATION_LEASE_TIMEOUT_SECONDS_ENV,
            "-1",
        ),
        (
            PHISHTANK_NORMALIZATION_MAX_ATTEMPTS_ENV,
            "1.5",
        ),
    ],
)
def test_invalid_environment_is_rejected_before_connection(
    variable_name: str,
    invalid_value: str,
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
            match=variable_name,
        ):
            build_phishtank_normalization_job(
                source_id=uuid4()
            )

    create_engine.assert_not_called()


def test_invalid_source_id_is_rejected(
) -> None:
    with pytest.raises(
        TypeError,
        match="source_id",
    ):
        build_phishtank_normalization_job(
            source_id=(
                "invalid"
            ),  # type: ignore[arg-type]
        )