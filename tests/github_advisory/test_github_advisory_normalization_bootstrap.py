from __future__ import annotations

from datetime import timedelta
from unittest.mock import Mock, patch
from uuid import uuid4

import pytest

from infrastructure.bootstrap.github_advisory_normalization import (
    DEFAULT_BATCH_SIZE,
    DEFAULT_LEASE_TIMEOUT_SECONDS,
    DEFAULT_MAX_ATTEMPTS,
    DEFAULT_MAX_BATCHES,
    GITHUB_ADVISORY_NORMALIZATION_BATCH_SIZE_ENV,
    GITHUB_ADVISORY_NORMALIZATION_LEASE_TIMEOUT_SECONDS_ENV,
    GITHUB_ADVISORY_NORMALIZATION_MAX_ATTEMPTS_ENV,
    GITHUB_ADVISORY_NORMALIZATION_MAX_BATCHES_ENV,
    GITHUB_ADVISORY_SOURCE_CODE,
    build_github_advisory_normalization_job,
)


BOOTSTRAP_MODULE = (
    "infrastructure.bootstrap."
    "github_advisory_normalization"
)


def _remove_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for variable_name in (
        GITHUB_ADVISORY_NORMALIZATION_BATCH_SIZE_ENV,
        GITHUB_ADVISORY_NORMALIZATION_MAX_BATCHES_ENV,
        GITHUB_ADVISORY_NORMALIZATION_LEASE_TIMEOUT_SECONDS_ENV,
        GITHUB_ADVISORY_NORMALIZATION_MAX_ATTEMPTS_ENV,
    ):
        monkeypatch.delenv(
            variable_name,
            raising=False,
        )


def test_build_job_composes_dependencies_with_defaults(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _remove_environment(monkeypatch)

    source_id = uuid4()

    engine = Mock()
    session_factory = Mock()
    unit_of_work = Mock()
    normalizer = Mock()
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
            "GitHubAdvisoryNormalizer",
            return_value=normalizer,
        ) as normalizer_class,
        patch(
            f"{BOOTSTRAP_MODULE}."
            "GitHubAdvisoryNormalizationService",
            return_value=service,
        ) as service_class,
        patch(
            f"{BOOTSTRAP_MODULE}."
            "GitHubAdvisoryNormalizationJob",
            return_value=expected_job,
        ) as job_class,
    ):
        result = (
            build_github_advisory_normalization_job(
                source_id=source_id,
            )
        )

    create_engine.assert_called_once_with()

    create_factory.assert_called_once_with(
        engine
    )

    unit_of_work_class.assert_called_once_with(
        session_factory=session_factory,
    )

    normalizer_class.assert_called_once_with()

    service_class.assert_called_once_with(
        unit_of_work=unit_of_work,
        normalizer=normalizer,
        lease_timeout=timedelta(
            seconds=(
                DEFAULT_LEASE_TIMEOUT_SECONDS
            )
        ),
        max_attempts=DEFAULT_MAX_ATTEMPTS,
    )

    job_class.assert_called_once_with(
        normalization_service=service,
        source_id=source_id,
        source_code=(
            GITHUB_ADVISORY_SOURCE_CODE
        ),
        batch_size=DEFAULT_BATCH_SIZE,
        max_batches=DEFAULT_MAX_BATCHES,
    )

    assert result is expected_job


def test_build_job_uses_environment_configuration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        GITHUB_ADVISORY_NORMALIZATION_BATCH_SIZE_ENV,
        " 25 ",
    )

    monkeypatch.setenv(
        GITHUB_ADVISORY_NORMALIZATION_MAX_BATCHES_ENV,
        " 500 ",
    )

    monkeypatch.setenv(
        GITHUB_ADVISORY_NORMALIZATION_LEASE_TIMEOUT_SECONDS_ENV,
        " 120 ",
    )

    monkeypatch.setenv(
        GITHUB_ADVISORY_NORMALIZATION_MAX_ATTEMPTS_ENV,
        " 5 ",
    )

    source_id = uuid4()

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
            "GitHubAdvisoryNormalizer",
            return_value=Mock(),
        ),
        patch(
            f"{BOOTSTRAP_MODULE}."
            "GitHubAdvisoryNormalizationService",
            return_value=Mock(),
        ) as service_class,
        patch(
            f"{BOOTSTRAP_MODULE}."
            "GitHubAdvisoryNormalizationJob",
            return_value=Mock(),
        ) as job_class,
    ):
        build_github_advisory_normalization_job(
            source_id=source_id,
        )

    service_class.assert_called_once()

    assert (
        service_class.call_args.kwargs[
            "lease_timeout"
        ]
        == timedelta(seconds=120)
    )

    assert (
        service_class.call_args.kwargs[
            "max_attempts"
        ]
        == 5
    )

    assert (
        job_class.call_args.kwargs[
            "batch_size"
        ]
        == 25
    )

    assert (
        job_class.call_args.kwargs[
            "max_batches"
        ]
        == 500
    )


def test_build_job_rejects_invalid_source_id(
) -> None:
    with pytest.raises(
        TypeError,
        match="source_id must be a UUID",
    ):
        build_github_advisory_normalization_job(
            source_id=(
                "invalid"
            ),  # type: ignore[arg-type]
        )


@pytest.mark.parametrize(
    (
        "variable_name, invalid_value, "
        "expected_message"
    ),
    [
        (
            GITHUB_ADVISORY_NORMALIZATION_BATCH_SIZE_ENV,
            "",
            (
                "GITHUB_ADVISORY_NORMALIZATION_"
                "BATCH_SIZE must not be empty"
            ),
        ),
        (
            GITHUB_ADVISORY_NORMALIZATION_BATCH_SIZE_ENV,
            "invalid",
            (
                "GITHUB_ADVISORY_NORMALIZATION_"
                "BATCH_SIZE must be an integer"
            ),
        ),
        (
            GITHUB_ADVISORY_NORMALIZATION_MAX_BATCHES_ENV,
            "0",
            (
                "GITHUB_ADVISORY_NORMALIZATION_"
                "MAX_BATCHES must be greater "
                "than zero"
            ),
        ),
        (
            GITHUB_ADVISORY_NORMALIZATION_LEASE_TIMEOUT_SECONDS_ENV,
            "-1",
            (
                "GITHUB_ADVISORY_NORMALIZATION_"
                "LEASE_TIMEOUT_SECONDS must be "
                "greater than zero"
            ),
        ),
        (
            GITHUB_ADVISORY_NORMALIZATION_MAX_ATTEMPTS_ENV,
            "1.5",
            (
                "GITHUB_ADVISORY_NORMALIZATION_"
                "MAX_ATTEMPTS must be an integer"
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
    _remove_environment(monkeypatch)

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
            build_github_advisory_normalization_job(
                source_id=uuid4(),
            )

    # Aucune connexion n'est ouverte lorsque
    # la configuration est invalide.
    create_engine.assert_not_called()