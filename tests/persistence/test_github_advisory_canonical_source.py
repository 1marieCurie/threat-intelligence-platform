from __future__ import annotations

from datetime import (
    UTC,
    datetime,
)
from unittest.mock import Mock
from uuid import UUID

import pytest
from sqlalchemy.dialects import (
    postgresql,
)
from sqlalchemy.orm import Session

from application.models.github_advisory_canonical_source_record import (
    GitHubAdvisoryCanonicalCursor,
    GitHubAdvisoryCanonicalSourceRecord,
)
from infrastructure.persistence.sqlalchemy.readers.github_advisory_canonical_source import (
    SqlAlchemyGitHubAdvisoryCanonicalSource,
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
            str | None,
            list[str] | None,
            datetime | None,
            datetime | None,
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
        SqlAlchemyGitHubAdvisoryCanonicalSource(
            session=None,  # type: ignore[arg-type]
        )


def test_read_batch_maps_projection_with_one_query(
) -> None:
    normalized_at = datetime(
        2026,
        8,
        4,
        12,
        0,
        tzinfo=UTC,
    )

    published_at = datetime(
        2026,
        8,
        2,
        10,
        0,
        tzinfo=UTC,
    )

    updated_at = datetime(
        2026,
        8,
        3,
        11,
        0,
        tzinfo=UTC,
    )

    session = _build_session(
        rows=[
            (
                _FIRST_ID,
                "GHSA-ABCD-1234-EFGH",
                "CVE-2026-12345",
                [
                    "CWE-79",
                    "cwe-89",
                    "invalid",
                    "CWE-079",
                ],
                published_at,
                updated_at,
                normalized_at,
            ),
        ]
    )

    records = (
        SqlAlchemyGitHubAdvisoryCanonicalSource(
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
        record.ghsa_id
        == "GHSA-ABCD-1234-EFGH"
    )

    assert (
        record.source_ghsa_id
        == "GHSA-ABCD-1234-EFGH"
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
        record.published_at
        == published_at
    )

    assert record.updated_at == updated_at

    assert (
        record.normalized_at
        == normalized_at
    )

    assert record.withdrawn_at is None
    assert record.is_withdrawn is False

    assert record.cursor == (
        GitHubAdvisoryCanonicalCursor(
            ghsa_id=(
                "GHSA-ABCD-1234-EFGH"
            ),
            normalized_record_id=(
                _FIRST_ID
            ),
        )
    )

    session.execute.assert_called_once()


def test_read_batch_uses_composite_keyset_and_filters_withdrawn(
) -> None:
    session = _build_session(
        rows=[]
    )

    cursor = GitHubAdvisoryCanonicalCursor(
        ghsa_id="ghsa-abcd-1234-efgh",
        normalized_record_id=_FIRST_ID,
    )

    result = (
        SqlAlchemyGitHubAdvisoryCanonicalSource(
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

    assert "withdrawn_at is null" in sql
    assert " > " in sql
    assert "order by" in sql
    assert "ghsa_id asc" in sql
    assert "id asc" in sql
    assert "limit 10" in sql
    assert "offset" not in sql


def test_read_batch_selects_only_required_columns(
) -> None:
    session = _build_session(
        rows=[]
    )

    SqlAlchemyGitHubAdvisoryCanonicalSource(
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
        "github_advisory_vulnerability"
        in sql
    )

    assert "raw.source_payload" not in sql
    assert "select *" not in sql

    for column_name in (
        "id",
        "ghsa_id",
        "cve_id",
        "cwe_ids",
        "published_at",
        "updated_at",
        "normalized_at",
    ):
        assert column_name in sql

    for forbidden_column in (
        "description",
        "summary",
        "cvss_score",
        "cvss_metrics",
        "affected_packages",
        "references",
        "html_url",
    ):
        assert forbidden_column not in sql


def test_read_batch_preserves_duplicate_ghsa_rows(
) -> None:
    normalized_at = datetime(
        2026,
        8,
        4,
        12,
        0,
        tzinfo=UTC,
    )

    session = _build_session(
        rows=[
            (
                _FIRST_ID,
                "GHSA-ABCD-1234-EFGH",
                None,
                [],
                None,
                None,
                normalized_at,
            ),
            (
                _SECOND_ID,
                "GHSA-ABCD-1234-EFGH",
                "CVE-2026-12345",
                [
                    "CWE-79",
                ],
                None,
                None,
                normalized_at,
            ),
        ]
    )

    result = (
        SqlAlchemyGitHubAdvisoryCanonicalSource(
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
        record.ghsa_id
        == "GHSA-ABCD-1234-EFGH"
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
        0,
        tzinfo=UTC,
    )

    session = _build_session(
        rows=[
            (
                _FIRST_ID,
                "GHSA-ABCD-1234-EFGH",
                None,
                None,
                None,
                None,
                normalized_at,
            ),
        ]
    )

    result = (
        SqlAlchemyGitHubAdvisoryCanonicalSource(
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
        SqlAlchemyGitHubAdvisoryCanonicalSource(
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
        SqlAlchemyGitHubAdvisoryCanonicalSource(
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
        SqlAlchemyGitHubAdvisoryCanonicalSource(
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
            "GitHubAdvisoryCanonicalCursor "
            "or None"
        ),
    ):
        SqlAlchemyGitHubAdvisoryCanonicalSource(
            session=session,
        ).read_batch(
            after_cursor=object(),  # type: ignore[arg-type]
        )

    session.execute.assert_not_called()


def test_cursor_preserves_database_ghsa_case(
) -> None:
    cursor = GitHubAdvisoryCanonicalCursor(
        ghsa_id="GHSA-abcd-1234-efgh",
        normalized_record_id=_FIRST_ID,
    )

    assert (
        cursor.ghsa_id
        == "GHSA-abcd-1234-efgh"
    )


def test_record_separates_canonical_and_storage_ghsa(
) -> None:
    record = (
        GitHubAdvisoryCanonicalSourceRecord(
            normalized_record_id=_FIRST_ID,
            ghsa_id="GHSA-abcd-1234-efgh",
            source_ghsa_id=(
                "GHSA-abcd-1234-efgh"
            ),
            cwe_ids=(
                "cwe-79",
                "CWE-079",
                "invalid",
            ),
            normalized_at=datetime(
                2026,
                8,
                4,
                12,
                0,
                tzinfo=UTC,
            ),
        )
    )

    assert (
        record.ghsa_id
        == "GHSA-ABCD-1234-EFGH"
    )

    assert (
        record.source_ghsa_id
        == "GHSA-abcd-1234-efgh"
    )

    assert (
        record.cursor.ghsa_id
        == "GHSA-abcd-1234-efgh"
    )

    assert record.cwe_ids == (
        "CWE-79",
    )


def test_record_rejects_mismatched_storage_ghsa(
) -> None:
    with pytest.raises(
        ValueError,
        match=(
            "source_ghsa_id and ghsa_id "
            "must identify the same advisory"
        ),
    ):
        GitHubAdvisoryCanonicalSourceRecord(
            normalized_record_id=_FIRST_ID,
            ghsa_id="GHSA-abcd-1234-efgh",
            source_ghsa_id=(
                "GHSA-1111-2222-3333"
            ),
            normalized_at=datetime(
                2026,
                8,
                4,
                12,
                0,
                tzinfo=UTC,
            ),
        )