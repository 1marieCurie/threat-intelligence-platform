from __future__ import annotations

from unittest.mock import Mock

from sqlalchemy.dialects import (
    postgresql,
)
from sqlalchemy.orm import Session

from infrastructure.persistence.sqlalchemy.readers.github_advisory_canonical_source import (
    SqlAlchemyGitHubAdvisoryCanonicalSource,
)


def _session() -> Mock:
    session = Mock(
        spec=Session
    )

    session.execute.return_value \
        .tuples.return_value \
        .all.return_value = []

    return session


def test_incremental_mode_filters_already_canonicalized_records():
    session = _session()

    source = (
        SqlAlchemyGitHubAdvisoryCanonicalSource(
            session=session,
            incremental_only=True,
        )
    )

    result = source.read_batch(
        limit=500
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
        "row_number() over"
        in sql
    )

    assert (
        "canonical."
        "canonical_vulnerability_evidence"
        in sql
    )

    assert (
        "github_advisory"
        in sql
    )

    assert (
        "normalized_record_id"
        in sql
    )

    assert (
        "version_rank = 1"
        in sql
        or "version_rank = 1"
        in sql.replace(
            "%(version_rank_1)s",
            "1",
        )
    )

    assert (
        "left outer join"
        in sql
    )

    assert (
        "order by"
        in sql
    )

    assert (
        "limit 500"
        in sql
    )


def test_default_mode_keeps_full_backfill_behavior():
    session = _session()

    source = (
        SqlAlchemyGitHubAdvisoryCanonicalSource(
            session=session
        )
    )

    source.read_batch(
        limit=50
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
        "canonical_vulnerability_evidence"
        not in sql
    )

    assert (
        "row_number() over"
        not in sql
    )

    assert (
        "normalized."
        "github_advisory_vulnerability"
        in sql
    )