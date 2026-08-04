from __future__ import annotations

from datetime import (
    UTC,
    date,
    datetime,
    timedelta,
    timezone,
)
from unittest.mock import Mock

import pytest
from sqlalchemy.dialects import (
    postgresql,
)
from sqlalchemy.orm import Session

from infrastructure.persistence.sqlalchemy.readers.epss_canonical_source import (
    SqlAlchemyEPSSCanonicalSource,
)


def _build_session(
    *,
    rows: list[
        tuple[
            str,
            float,
            float,
            date,
            str | None,
            datetime,
        ]
    ],
) -> Mock:
    session = Mock(
        spec=Session,
    )

    session.execute.return_value \
        .tuples.return_value \
        .all.return_value = rows

    return session


def test_constructor_rejects_missing_session(
) -> None:
    with pytest.raises(
        ValueError,
        match="session must not be None",
    ):
        SqlAlchemyEPSSCanonicalSource(
            session=None,  # type: ignore[arg-type]
        )


def test_read_batch_maps_projection_with_one_query(
) -> None:
    source_timezone = timezone(
        timedelta(
            hours=2
        )
    )

    session = _build_session(
        rows=[
            (
                "CVE-2026-10001",
                0.42,
                0.87,
                date(
                    2026,
                    8,
                    4,
                ),
                "v1",
                datetime(
                    2026,
                    8,
                    4,
                    14,
                    0,
                    tzinfo=source_timezone,
                ),
            ),
        ]
    )

    records = (
        SqlAlchemyEPSSCanonicalSource(
            session=session,
        )
        .read_batch(
            limit=25
        )
    )

    assert len(records) == 1

    record = records[0]

    assert (
        record.cve_id
        == "CVE-2026-10001"
    )

    assert record.snapshot.score == 0.42

    assert (
        record.snapshot.percentile
        == 0.87
    )

    assert (
        record.snapshot.score_date
        == date(
            2026,
            8,
            4,
        )
    )

    assert (
        record.snapshot.api_version
        == "v1"
    )

    assert (
        record.synchronized_at
        == datetime(
            2026,
            8,
            4,
            12,
            0,
            tzinfo=UTC,
        )
    )

    session.execute.assert_called_once()


def test_read_batch_uses_keyset_pagination(
) -> None:
    session = _build_session(
        rows=[]
    )

    records = (
        SqlAlchemyEPSSCanonicalSource(
            session=session,
        )
        .read_batch(
            after_cve_id=(
                "  cve-2026-10001  "
            ),
            limit=10,
        )
    )

    assert records == ()

    statement = (
        session.execute
        .call_args.args[0]
    )

    compiled = statement.compile(
        dialect=postgresql.dialect(),
        compile_kwargs={
            "literal_binds": True,
        },
    )

    sql = " ".join(
        str(compiled)
        .lower()
        .split()
    )

    assert (
        "where "
        "normalized.epss_score.cve_id "
        "> 'cve-2026-10001'"
        in sql
    )

    assert (
        "order by "
        "normalized.epss_score.cve_id asc"
        in sql
    )

    assert "limit 10" in sql


def test_read_batch_selects_only_normalized_columns(
) -> None:
    session = _build_session(
        rows=[]
    )

    SqlAlchemyEPSSCanonicalSource(
        session=session,
    ).read_batch(
        limit=1
    )

    statement = (
        session.execute
        .call_args.args[0]
    )

    compiled = statement.compile(
        dialect=postgresql.dialect(),
        compile_kwargs={
            "literal_binds": True,
        },
    )

    sql = " ".join(
        str(compiled)
        .lower()
        .split()
    )

    assert (
        "from normalized.epss_score"
        in sql
    )

    assert "raw.source_payload" not in sql
    assert "select *" not in sql

    for column_name in (
        "cve_id",
        "epss_score",
        "percentile",
        "score_date",
        "api_version",
        "synchronized_at",
    ):
        assert column_name in sql


def test_read_batch_returns_empty_tuple(
) -> None:
    session = _build_session(
        rows=[]
    )

    result = (
        SqlAlchemyEPSSCanonicalSource(
            session=session,
        )
        .read_batch()
    )

    assert result == ()
    session.execute.assert_called_once()


@pytest.mark.parametrize(
    "invalid_limit",
    [
        True,
        1.5,
        "100",
    ],
)
def test_read_batch_rejects_non_integer_limit(
    invalid_limit: object,
) -> None:
    session = _build_session(
        rows=[]
    )

    with pytest.raises(
        TypeError,
        match="limit must be an integer",
    ):
        SqlAlchemyEPSSCanonicalSource(
            session=session,
        ).read_batch(
            limit=invalid_limit,  # type: ignore[arg-type]
        )

    session.execute.assert_not_called()


@pytest.mark.parametrize(
    "invalid_limit",
    [
        0,
        -1,
        1_001,
    ],
)
def test_read_batch_rejects_out_of_range_limit(
    invalid_limit: int,
) -> None:
    session = _build_session(
        rows=[]
    )

    with pytest.raises(
        ValueError,
        match=(
            "limit must be between "
            "1 and 1000"
        ),
    ):
        SqlAlchemyEPSSCanonicalSource(
            session=session,
        ).read_batch(
            limit=invalid_limit
        )

    session.execute.assert_not_called()


def test_read_batch_rejects_invalid_cursor(
) -> None:
    session = _build_session(
        rows=[]
    )

    with pytest.raises(
        ValueError,
        match=(
            "value must be a valid "
            "CVE identifier"
        ),
    ):
        SqlAlchemyEPSSCanonicalSource(
            session=session,
        ).read_batch(
            after_cve_id="invalid"
        )

    session.execute.assert_not_called()