from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from unittest.mock import Mock

import pytest
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import Session

from domain.cwe_weakness import CWEWeakness
from infrastructure.persistence.models.normalized import (
    CWEWeaknessModel,
)
from infrastructure.persistence.sqlalchemy.repositories.cwe_repository import (
    SqlAlchemyCWERepository,
)


def _build_weakness(
    *,
    cwe_id: str = "CWE-79",
    name: str = "Cross-site Scripting",
) -> CWEWeakness:
    return CWEWeakness(
        id=cwe_id,
        name=name,
        description=(
            "The application does not correctly "
            "neutralize user-controlled input."
        ),
        abstraction="Base",
        structure="Simple",
        status="Stable",
        extended_description=(
            "User-controlled input reaches "
            "generated web content."
        ),
        likelihood_of_exploit="High",
        mapping_usage="Allowed",
        mapping_rationale="Direct mapping",
        relationships=(
            {
                "nature": "ChildOf",
                "cwe_id": "CWE-74",
            },
        ),
        consequences=(
            {
                "scope": "Confidentiality",
                "impact": "Read Application Data",
            },
        ),
        mitigations=(
            {
                "phase": "Implementation",
                "description": "Encode output.",
            },
        ),
        detection_methods=(
            {
                "method": "Static Analysis",
            },
        ),
        applicable_platforms=(
            {
                "type": "Language",
                "name": "JavaScript",
            },
        ),
        modes_of_introduction=(
            {
                "phase": "Implementation",
            },
        ),
        alternate_terms=(
            "XSS",
        ),
        related_capec_ids=(
            "CAPEC-63",
        ),
        catalog_version="4.20",
        catalog_date="2026-04-30",
    )


def _build_model(
    *,
    cwe_id: str,
    name: str,
) -> CWEWeaknessModel:
    return CWEWeaknessModel(
        cwe_id=cwe_id,
        name=name,
        description="Description",
        abstraction="Base",
        structure="Simple",
        status="Stable",
        extended_description=None,
        likelihood_of_exploit="High",
        mapping_usage=None,
        mapping_rationale=None,
        relationships=[],
        consequences=[],
        mitigations=[],
        detection_methods=[],
        applicable_platforms=[],
        modes_of_introduction=[],
        alternate_terms=[],
        related_capec_ids=[],
        catalog_version="4.20",
        catalog_date="2026-04-30",
        synchronized_at=datetime.now(
            UTC
        ),
    )


def test_constructor_rejects_missing_session(
) -> None:
    with pytest.raises(
        ValueError,
        match="session must not be None",
    ):
        SqlAlchemyCWERepository(
            session=None,  # type: ignore[arg-type]
        )


def test_upsert_many_executes_postgresql_upsert(
) -> None:
    session = Mock(
        spec=Session,
    )

    repository = SqlAlchemyCWERepository(
        session=session,
    )

    result = repository.upsert_many(
        [
            _build_weakness(),
        ]
    )

    assert result == 1

    session.execute.assert_called_once()
    session.flush.assert_called_once_with()

    statement = (
        session.execute.call_args.args[0]
    )

    compiled = statement.compile(
        dialect=postgresql.dialect(),
    )

    sql = str(
        compiled
    ).upper()

    assert "ON CONFLICT" in sql
    assert "DO UPDATE" in sql

    assert "CWE-79" in (
        compiled.params.values()
    )


def test_upsert_many_normalizes_and_deduplicates_ids(
) -> None:
    session = Mock(
        spec=Session,
    )

    repository = SqlAlchemyCWERepository(
        session=session,
    )

    weakness = _build_weakness(
        cwe_id="cwe-00079",
    )

    result = repository.upsert_many(
        [
            weakness,
            weakness,
        ]
    )

    assert result == 1
    session.execute.assert_called_once()


def test_upsert_many_rejects_conflicting_duplicates(
) -> None:
    session = Mock(
        spec=Session,
    )

    repository = SqlAlchemyCWERepository(
        session=session,
    )

    first = _build_weakness()

    second = replace(
        first,
        id="cwe-00079",
        name="Different name",
    )

    with pytest.raises(
        ValueError,
        match=(
            "Conflicting duplicate CWE entry"
        ),
    ):
        repository.upsert_many(
            [
                first,
                second,
            ]
        )

    session.execute.assert_not_called()
    session.flush.assert_not_called()


def test_upsert_many_returns_zero_for_empty_collection(
) -> None:
    session = Mock(
        spec=Session,
    )

    repository = SqlAlchemyCWERepository(
        session=session,
    )

    assert repository.upsert_many([]) == 0

    session.execute.assert_not_called()
    session.flush.assert_not_called()


def test_find_by_id_maps_model_to_domain(
) -> None:
    session = Mock(
        spec=Session,
    )

    session.execute.return_value \
        .scalar_one_or_none.return_value = (
            _build_model(
                cwe_id="CWE-79",
                name="Cross-site Scripting",
            )
        )

    repository = SqlAlchemyCWERepository(
        session=session,
    )

    result = repository.find_by_id(
        "cwe-00079"
    )

    assert result is not None
    assert result.id == "CWE-79"
    assert result.name == (
        "Cross-site Scripting"
    )
    assert result.catalog_version == "4.20"


def test_find_by_id_returns_none_when_missing(
) -> None:
    session = Mock(
        spec=Session,
    )

    session.execute.return_value \
        .scalar_one_or_none.return_value = None

    repository = SqlAlchemyCWERepository(
        session=session,
    )

    assert (
        repository.find_by_id(
            "CWE-999"
        )
        is None
    )


def test_find_many_uses_one_query_and_preserves_order(
) -> None:
    session = Mock(
        spec=Session,
    )

    models = [
        _build_model(
            cwe_id="CWE-89",
            name="SQL Injection",
        ),
        _build_model(
            cwe_id="CWE-79",
            name="Cross-site Scripting",
        ),
    ]

    session.execute.return_value \
        .scalars.return_value \
        .all.return_value = models

    repository = SqlAlchemyCWERepository(
        session=session,
    )

    result = repository.find_many_by_ids(
        [
            "cwe-79",
            "CWE-89",
            "CWE-79",
        ]
    )

    assert [
        weakness.id
        for weakness in result
    ] == [
        "CWE-79",
        "CWE-89",
    ]

    session.execute.assert_called_once()


@pytest.mark.parametrize(
    "invalid_id",
    [
        "",
        "CWE-0",
        "CVE-2026-1234",
        "CWE-invalid",
    ],
)
def test_find_by_id_rejects_invalid_id(
    invalid_id: str,
) -> None:
    session = Mock(
        spec=Session,
    )

    repository = SqlAlchemyCWERepository(
        session=session,
    )

    with pytest.raises(
        ValueError,
        match=(
            "cwe_id must be a valid "
            "CWE identifier"
        ),
    ):
        repository.find_by_id(
            invalid_id
        )

    session.execute.assert_not_called()