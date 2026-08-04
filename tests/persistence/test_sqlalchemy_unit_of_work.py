from __future__ import annotations

from typing import (
    cast,
    get_type_hints,
)
from unittest.mock import Mock

import pytest
from sqlalchemy.orm import (
    Session,
    sessionmaker,
)

from application.ports.outbound.canonical_vulnerability_repository import (
    CanonicalVulnerabilityRepository,
)
from application.ports.outbound.unit_of_work import (
    UnitOfWork,
)
from infrastructure.persistence.sqlalchemy.repositories.canonical_vulnerability_repository import (
    SqlAlchemyCanonicalVulnerabilityRepository,
)
from infrastructure.persistence.sqlalchemy.repositories.cisa_kev_vulnerability_repository import (
    SqlAlchemyCisaKevVulnerabilityRepository,
)
from infrastructure.persistence.sqlalchemy.repositories.epss_score_repository import (
    SqlAlchemyEPSSScoreRepository,
)
from infrastructure.persistence.sqlalchemy.repositories.phishtank_phishing_repository import (
    SqlAlchemyPhishTankPhishingRepository,
)
from infrastructure.persistence.sqlalchemy.unit_of_work import (
    SqlAlchemyUnitOfWork,
)


def _build_unit_of_work(
) -> tuple[
    SqlAlchemyUnitOfWork,
    Mock,
]:
    session = Mock(
        spec=Session,
    )

    session_factory_mock = Mock(
        spec=sessionmaker,
        return_value=session,
    )

    session_factory = cast(
        sessionmaker[Session],
        session_factory_mock,
    )

    unit_of_work = SqlAlchemyUnitOfWork(
        session_factory=session_factory,
    )

    return (
        unit_of_work,
        session,
    )


def test_unit_of_work_protocol_exposes_canonical_repository(
) -> None:
    annotations = get_type_hints(
        UnitOfWork
    )

    assert annotations[
        "canonical_vulnerabilities"
    ] is CanonicalVulnerabilityRepository


def test_commit_delegates_to_session(
) -> None:
    unit_of_work, session = (
        _build_unit_of_work()
    )

    with unit_of_work:
        unit_of_work.commit()

    session.commit.assert_called_once_with()
    session.close.assert_called_once_with()


def test_exit_rolls_back_when_commit_is_not_called(
) -> None:
    unit_of_work, session = (
        _build_unit_of_work()
    )

    with unit_of_work:
        pass

    session.rollback.assert_called_once_with()
    session.close.assert_called_once_with()


def test_exit_rolls_back_on_exception(
) -> None:
    unit_of_work, session = (
        _build_unit_of_work()
    )

    with pytest.raises(
        ValueError,
    ):
        with unit_of_work:
            raise ValueError(
                "test failure"
            )

    session.rollback.assert_called_once_with()
    session.commit.assert_not_called()
    session.close.assert_called_once_with()


def test_commit_outside_context_is_rejected(
) -> None:
    unit_of_work, _ = (
        _build_unit_of_work()
    )

    with pytest.raises(
        RuntimeError,
        match="Unit of Work is not active",
    ):
        unit_of_work.commit()


def test_context_initializes_cisa_repository(
) -> None:
    unit_of_work, session = (
        _build_unit_of_work()
    )

    with unit_of_work:
        assert isinstance(
            unit_of_work
            .cisa_kev_vulnerabilities,
            SqlAlchemyCisaKevVulnerabilityRepository,
        )

    session.rollback.assert_called_once_with()
    session.close.assert_called_once_with()


def test_context_initializes_epss_repository(
) -> None:
    unit_of_work, session = (
        _build_unit_of_work()
    )

    with unit_of_work:
        assert isinstance(
            unit_of_work.epss_scores,
            SqlAlchemyEPSSScoreRepository,
        )

    session.rollback.assert_called_once_with()
    session.close.assert_called_once_with()


def test_context_initializes_phishtank_repository(
) -> None:
    unit_of_work, session = (
        _build_unit_of_work()
    )

    with unit_of_work:
        assert isinstance(
            unit_of_work.phishtank_phishing,
            SqlAlchemyPhishTankPhishingRepository,
        )

    session.rollback.assert_called_once_with()
    session.close.assert_called_once_with()


def test_context_initializes_canonical_repository(
) -> None:
    unit_of_work, session = (
        _build_unit_of_work()
    )

    with unit_of_work:
        repository = (
            unit_of_work
            .canonical_vulnerabilities
        )

        assert isinstance(
            repository,
            SqlAlchemyCanonicalVulnerabilityRepository,
        )

        assert getattr(
            repository,
            "_session",
        ) is session

    session.rollback.assert_called_once_with()
    session.close.assert_called_once_with()


def test_epss_repository_uses_unit_of_work_session(
) -> None:
    unit_of_work, session = (
        _build_unit_of_work()
    )

    session.execute.return_value \
        .scalar_one_or_none.return_value = None

    with unit_of_work:
        result = (
            unit_of_work
            .epss_scores
            .find_by_cve_id(
                "CVE-2021-44228"
            )
        )

        assert result is None

    session.execute.assert_called_once()
    session.rollback.assert_called_once_with()
    session.close.assert_called_once_with()


def test_unit_of_work_rejects_nested_context(
) -> None:
    unit_of_work, session = (
        _build_unit_of_work()
    )

    with unit_of_work:
        with pytest.raises(
            RuntimeError,
            match=(
                "Unit of Work is already active"
            ),
        ):
            unit_of_work.__enter__()

    session.rollback.assert_called_once_with()
    session.close.assert_called_once_with()