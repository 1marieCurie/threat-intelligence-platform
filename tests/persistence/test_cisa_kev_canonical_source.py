from __future__ import annotations

from datetime import (
    UTC,
    date,
    datetime,
)
from unittest.mock import Mock
from uuid import UUID

import pytest
from sqlalchemy.dialects import (
    postgresql,
)
from sqlalchemy.orm import Session

from application.models.cisa_kev_canonical_source_record import (
    CisaKevCanonicalCursor,
    CisaKevCanonicalSourceRecord,
)
from infrastructure.persistence.sqlalchemy.readers.cisa_kev_canonical_source import (
    SqlAlchemyCisaKevCanonicalSource,
)


_FIRST_ID = UUID(
    "00000000-0000-0000-0000-000000000001"
)

_SECOND_ID = UUID(
    "00000000-0000-0000-0000-000000000002"
)


def _build_session(
    *,
    rows: list[
        tuple[
            UUID,
            str,
            list[str] | None,
            date,
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
        SqlAlchemyCisaKevCanonicalSource(
            session=None,  # type: ignore[arg-type]
        )


def test_read_batch_maps_projection_with_one_query(
) -> None:
    normalized_at = datetime(
        2026,
        8,
        4,
        12,
        30,
        tzinfo=UTC,
    )

    session = _build_session(
        rows=[
            (
                _FIRST_ID,
                "CVE-2026-12345",
                [
                    "CWE-79",
                    "cwe-89",
                    "invalid",
                    "CWE-079",
                ],
                date(
                    2026,
                    8,
                    3,
                ),
                normalized_at,
            ),
        ]
    )

    records = (
        SqlAlchemyCisaKevCanonicalSource(
            session=session,
        )
        .read_batch(
            limit=25
        )
    )

    assert len(records) == 1

    record = records[0]

    assert (
        record.normalized_record_id
        == _FIRST_ID
    )

    assert (
        record.cve_id
        == "CVE-2026-12345"
    )

    assert record.cwe_ids == (
        "CWE-79",
        "CWE-89",
    )

    assert (
        record.date_added
        == date(
            2026,
            8,
            3,
        )
    )

    assert (
        record.normalized_at
        == normalized_at
    )

    assert record.cursor == (
        CisaKevCanonicalCursor(
            cve_id="CVE-2026-12345",
            normalized_record_id=(
                _FIRST_ID
            ),
        )
    )

    session.execute.assert_called_once()


def test_read_batch_uses_composite_keyset_cursor(
) -> None:
    session = _build_session(
        rows=[]
    )

    cursor = CisaKevCanonicalCursor(
        cve_id="cve-2026-12345",
        normalized_record_id=(
            _FIRST_ID
        ),
    )

    result = (
        SqlAlchemyCisaKevCanonicalSource(
            session=session,
        )
        .read_batch(
            after_cursor=cursor,
            limit=10,
        )
    )

    assert result == ()

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
        "normalized."
        "cisa_kev_vulnerability.cve_id"
        in sql
    )

    assert (
        "normalized."
        "cisa_kev_vulnerability.id"
        in sql
    )

    assert " > " in sql
    assert "order by" in sql
    assert "cve_id asc" in sql
    assert "id asc" in sql
    assert "limit 10" in sql
    assert "offset" not in sql


def test_read_batch_selects_only_normalized_columns(
) -> None:
    session = _build_session(
        rows=[]
    )

    SqlAlchemyCisaKevCanonicalSource(
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
        "from normalized."
        "cisa_kev_vulnerability"
        in sql
    )

    assert "raw.source_payload" not in sql
    assert "select *" not in sql

    for column_name in (
        "id",
        "cve_id",
        "cwes",
        "date_added",
        "normalized_at",
    ):
        assert column_name in sql

    for forbidden_column in (
        "short_description",
        "required_action",
        "notes",
        "vendor_project",
    ):
        assert forbidden_column not in sql


def test_read_batch_preserves_duplicate_cve_rows(
) -> None:
    session = _build_session(
        rows=[
            (
                _FIRST_ID,
                "CVE-2026-12345",
                [],
                date(
                    2026,
                    8,
                    3,
                ),
                datetime(
                    2026,
                    8,
                    3,
                    12,
                    tzinfo=UTC,
                ),
            ),
            (
                _SECOND_ID,
                "CVE-2026-12345",
                [
                    "CWE-79",
                ],
                date(
                    2026,
                    8,
                    3,
                ),
                datetime(
                    2026,
                    8,
                    4,
                    12,
                    tzinfo=UTC,
                ),
            ),
        ]
    )

    result = (
        SqlAlchemyCisaKevCanonicalSource(
            session=session,
        )
        .read_batch(
            limit=2
        )
    )

    assert len(result) == 2

    assert [
        record.normalized_record_id
        for record in result
    ] == [
        _FIRST_ID,
        _SECOND_ID,
    ]

    assert all(
        record.cve_id
        == "CVE-2026-12345"
        for record in result
    )

    assert result[0].cwe_ids == ()

    assert result[1].cwe_ids == (
        "CWE-79",
    )


def test_read_batch_handles_null_cwe_collection(
) -> None:
    normalized_at = datetime(
        2026,
        8,
        4,
        12,
        tzinfo=UTC,
    )

    session = _build_session(
        rows=[
            (
                _FIRST_ID,
                "CVE-2026-12345",
                None,
                date(
                    2026,
                    8,
                    3,
                ),
                normalized_at,
            ),
        ]
    )

    result = (
        SqlAlchemyCisaKevCanonicalSource(
            session=session,
        )
        .read_batch()
    )

    assert result[0].cwe_ids == ()


def test_read_batch_returns_empty_tuple(
) -> None:
    session = _build_session(
        rows=[]
    )

    result = (
        SqlAlchemyCisaKevCanonicalSource(
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
        SqlAlchemyCisaKevCanonicalSource(
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
        SqlAlchemyCisaKevCanonicalSource(
            session=session,
        ).read_batch(
            limit=invalid_limit
        )

    session.execute.assert_not_called()


def test_read_batch_rejects_invalid_cursor_type(
) -> None:
    session = _build_session(
        rows=[]
    )

    with pytest.raises(
        TypeError,
        match=(
            "after_cursor must be a "
            "CisaKevCanonicalCursor or None"
        ),
    ):
        SqlAlchemyCisaKevCanonicalSource(
            session=session,
        ).read_batch(
            after_cursor=object(),  # type: ignore[arg-type]
        )

    session.execute.assert_not_called()


def test_record_normalizes_cwe_identifiers(
) -> None:
    record = CisaKevCanonicalSourceRecord(
        normalized_record_id=_FIRST_ID,
        cve_id="cve-2026-12345",
        cwe_ids=(
            "cwe-79",
            "79",
            "CWE-089",
            "invalid",
        ),
        date_added=date(
            2026,
            8,
            3,
        ),
        normalized_at=datetime(
            2026,
            8,
            4,
            12,
            tzinfo=UTC,
        ),
    )

    assert record.cve_id == (
        "CVE-2026-12345"
    )

    assert record.cwe_ids == (
        "CWE-79",
        "CWE-89",
    )