from __future__ import annotations

from unittest.mock import Mock

import pytest
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import Session

from infrastructure.persistence.sqlalchemy.repositories.cwe_reference_repository import (
    SqlAlchemyVulnerabilityCWEReferenceRepository,
)


def test_constructor_rejects_missing_session(
) -> None:
    with pytest.raises(
        ValueError,
        match="session must not be None",
    ):
        SqlAlchemyVulnerabilityCWEReferenceRepository(
            session=None,  # type: ignore[arg-type]
        )


def test_list_distinct_ids_executes_bounded_query(
) -> None:
    session = Mock(
        spec=Session,
    )

    session.execute.return_value \
        .scalars.return_value \
        .all.return_value = [
            "CWE-79",
            "CWE-89",
        ]

    repository = (
        SqlAlchemyVulnerabilityCWEReferenceRepository(
            session=session,
        )
    )

    result = repository.list_distinct_ids(
        limit=100
    )

    assert result == [
        "CWE-79",
        "CWE-89",
    ]

    statement = (
        session.execute.call_args.args[0]
    )

    sql = str(
        statement.compile(
            dialect=postgresql.dialect(),
        )
    ).upper()

    assert "UNNEST" in sql
    assert "DISTINCT" in sql
    assert "LIMIT" in sql


@pytest.mark.parametrize(
    "invalid_limit",
    [
        0,
        -1,
    ],
)
def test_rejects_non_positive_limit(
    invalid_limit: int,
) -> None:
    session = Mock(
        spec=Session,
    )

    repository = (
        SqlAlchemyVulnerabilityCWEReferenceRepository(
            session=session,
        )
    )

    with pytest.raises(
        ValueError,
        match="greater than zero",
    ):
        repository.list_distinct_ids(
            limit=invalid_limit
        )


@pytest.mark.parametrize(
    "invalid_limit",
    [
        True,
        1.5,
        "100",
        None,
    ],
)
def test_rejects_invalid_limit_type(
    invalid_limit: object,
) -> None:
    session = Mock(
        spec=Session,
    )

    repository = (
        SqlAlchemyVulnerabilityCWEReferenceRepository(
            session=session,
        )
    )

    with pytest.raises(
        TypeError,
        match="limit must be an integer",
    ):
        repository.list_distinct_ids(
            limit=invalid_limit,  # type: ignore[arg-type]
        )