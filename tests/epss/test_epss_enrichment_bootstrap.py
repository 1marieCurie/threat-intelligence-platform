from __future__ import annotations

from unittest.mock import Mock, patch

import pytest

from infrastructure.bootstrap.epss_enrichment import (
    DEFAULT_MAX_CVE_IDS,
    EPSS_ENRICHMENT_MAX_CVE_IDS_ENV,
    MAX_ALLOWED_CVE_IDS,
    build_epss_enrichment_service,
)


BOOTSTRAP_MODULE = (
    "infrastructure.bootstrap."
    "epss_enrichment"
)


def _remove_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv(
        EPSS_ENRICHMENT_MAX_CVE_IDS_ENV,
        raising=False,
    )


def test_build_service_composes_defaults(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _remove_environment(
        monkeypatch
    )

    engine = Mock()
    session_factory = Mock()
    unit_of_work = Mock()
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
            "EPSSEnrichmentService",
            return_value=expected_service,
        ) as service_class,
    ):
        result = (
            build_epss_enrichment_service()
        )

    create_engine.assert_called_once_with()

    create_factory.assert_called_once_with(
        engine
    )

    unit_of_work_class.assert_called_once_with(
        session_factory=session_factory,
    )

    service_class.assert_called_once_with(
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
        EPSS_ENRICHMENT_MAX_CVE_IDS_ENV,
        " 1200 ",
    )

    engine = Mock()
    session_factory = Mock()
    unit_of_work = Mock()
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
            "EPSSEnrichmentService",
            return_value=expected_service,
        ) as service_class,
    ):
        result = (
            build_epss_enrichment_service()
        )

    service_class.assert_called_once_with(
        unit_of_work=unit_of_work,
        max_cve_ids=1200,
    )

    assert result is expected_service


@pytest.mark.parametrize(
    (
        "invalid_value",
        "expected_message",
    ),
    [
        (
            "",
            (
                "EPSS_ENRICHMENT_MAX_CVE_IDS "
                "must not be empty"
            ),
        ),
        (
            "invalid",
            (
                "EPSS_ENRICHMENT_MAX_CVE_IDS "
                "must be an integer"
            ),
        ),
        (
            "1.5",
            (
                "EPSS_ENRICHMENT_MAX_CVE_IDS "
                "must be an integer"
            ),
        ),
        (
            "0",
            (
                "EPSS_ENRICHMENT_MAX_CVE_IDS "
                "must be greater than zero"
            ),
        ),
        (
            "-1",
            (
                "EPSS_ENRICHMENT_MAX_CVE_IDS "
                "must be greater than zero"
            ),
        ),
    ],
)
def test_build_service_rejects_invalid_environment(
    invalid_value: str,
    expected_message: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _remove_environment(
        monkeypatch
    )

    monkeypatch.setenv(
        EPSS_ENRICHMENT_MAX_CVE_IDS_ENV,
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
            build_epss_enrichment_service()

    # Une configuration invalide ne doit pas créer
    # de pool PostgreSQL.
    create_engine.assert_not_called()


def test_build_service_rejects_oversized_configuration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _remove_environment(
        monkeypatch
    )

    monkeypatch.setenv(
        EPSS_ENRICHMENT_MAX_CVE_IDS_ENV,
        str(
            MAX_ALLOWED_CVE_IDS + 1
        ),
    )

    with patch(
        f"{BOOTSTRAP_MODULE}."
        "create_ingestion_engine"
    ) as create_engine:
        with pytest.raises(
            RuntimeError,
            match=(
                "EPSS_ENRICHMENT_MAX_CVE_IDS "
                "must not exceed 50000"
            ),
        ):
            build_epss_enrichment_service()

    create_engine.assert_not_called()