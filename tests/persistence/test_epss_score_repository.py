from __future__ import annotations

from datetime import UTC, date, datetime
from unittest.mock import Mock

import pytest
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import Session

from application.models.epss_snapshot import (
    EPSSSnapshot,
)
from infrastructure.persistence.models.normalized import (
    EPSSScoreModel,
)
from infrastructure.persistence.sqlalchemy.repositories.epss_score_repository import (
    SqlAlchemyEPSSScoreRepository,
)


def _build_snapshot(
    *,
    score: float = 0.85,
    percentile: float = 0.97,
    score_date: date = date(
        2026,
        7,
        30,
    ),
    api_version: str | None = "v2026.07",
) -> EPSSSnapshot:
    return EPSSSnapshot(
        score=score,
        percentile=percentile,
        score_date=score_date,
        api_version=api_version,
    )


def _build_model(
    *,
    cve_id: str,
    score: float = 0.85,
    percentile: float = 0.97,
    score_date: date = date(
        2026,
        7,
        30,
    ),
) -> EPSSScoreModel:
    return EPSSScoreModel(
        cve_id=cve_id,
        epss_score=score,
        percentile=percentile,
        score_date=score_date,
        api_version="v2026.07",
        synchronized_at=datetime.now(
            UTC
        ),
    )


def test_constructor_rejects_missing_session() -> None:
    with pytest.raises(
        ValueError,
        match="session must not be None",
    ):
        SqlAlchemyEPSSScoreRepository(
            session=None,  # type: ignore[arg-type]
        )


def test_find_by_cve_id_maps_model_to_snapshot() -> None:
    session = Mock(
        spec=Session,
    )

    session.execute.return_value \
        .scalar_one_or_none.return_value = (
            _build_model(
                cve_id="CVE-2021-44228",
            )
        )

    repository = SqlAlchemyEPSSScoreRepository(
        session=session,
    )

    result = repository.find_by_cve_id(
        "cve-2021-44228"
    )

    assert result is not None
    assert result.score == 0.85
    assert result.percentile == 0.97
    assert result.score_date == date(
        2026,
        7,
        30,
    )
    assert result.api_version == "v2026.07"

    session.execute.assert_called_once()


def test_find_by_cve_id_returns_none_when_missing() -> None:
    session = Mock(
        spec=Session,
    )

    session.execute.return_value \
        .scalar_one_or_none.return_value = None

    repository = SqlAlchemyEPSSScoreRepository(
        session=session,
    )

    result = repository.find_by_cve_id(
        "CVE-2021-44228"
    )

    assert result is None
    session.execute.assert_called_once()


def test_find_many_uses_one_query_and_preserves_order() -> None:
    session = Mock(
        spec=Session,
    )

    session.execute.return_value \
        .scalars.return_value \
        .all.return_value = [
            _build_model(
                cve_id="CVE-2023-34362",
                score=0.91,
            ),
            _build_model(
                cve_id="CVE-2021-44228",
                score=0.99,
            ),
        ]

    repository = SqlAlchemyEPSSScoreRepository(
        session=session,
    )

    result = repository.find_many_by_cve_ids(
        [
            "cve-2021-44228",
            "CVE-2023-34362",
            "CVE-2021-44228",
        ]
    )

    assert list(
        result
    ) == [
        "CVE-2021-44228",
        "CVE-2023-34362",
    ]

    assert result[
        "CVE-2021-44228"
    ].score == 0.99

    assert result[
        "CVE-2023-34362"
    ].score == 0.91

    session.execute.assert_called_once()


def test_find_many_returns_empty_for_empty_collection() -> None:
    session = Mock(
        spec=Session,
    )

    repository = SqlAlchemyEPSSScoreRepository(
        session=session,
    )

    result = repository.find_many_by_cve_ids(
        []
    )

    assert result == {}
    session.execute.assert_not_called()


@pytest.mark.parametrize(
    "invalid_cve_id",
    [
        "",
        "CVE-2026-123",
        "CVE-26-1234",
        "CWE-79",
        "invalid",
    ],
)
def test_find_by_cve_id_rejects_invalid_identifier(
    invalid_cve_id: str,
) -> None:
    session = Mock(
        spec=Session,
    )

    repository = SqlAlchemyEPSSScoreRepository(
        session=session,
    )

    with pytest.raises(
        ValueError,
        match=(
            "cve_id must be a valid "
            "CVE identifier"
        ),
    ):
        repository.find_by_cve_id(
            invalid_cve_id
        )

    session.execute.assert_not_called()


def test_find_by_cve_id_rejects_invalid_type() -> None:
    session = Mock(
        spec=Session,
    )

    repository = SqlAlchemyEPSSScoreRepository(
        session=session,
    )

    with pytest.raises(
        TypeError,
        match="cve_id must be a string",
    ):
        repository.find_by_cve_id(
            1234  # type: ignore[arg-type]
        )

    session.execute.assert_not_called()


def test_find_many_rejects_string_instead_of_iterable() -> None:
    session = Mock(
        spec=Session,
    )

    repository = SqlAlchemyEPSSScoreRepository(
        session=session,
    )

    with pytest.raises(
        TypeError,
        match=(
            "cve_ids must be an iterable "
            "of strings"
        ),
    ):
        repository.find_many_by_cve_ids(
            "CVE-2021-44228"
        )

    session.execute.assert_not_called()


def test_upsert_many_executes_postgresql_upsert() -> None:
    session = Mock(
        spec=Session,
    )

    repository = SqlAlchemyEPSSScoreRepository(
        session=session,
    )

    result = repository.upsert_many(
        {
            "CVE-2021-44228": (
                _build_snapshot()
            ),
        }
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
    assert "WHERE" in sql
    assert "SCORE_DATE" in sql

    assert "CVE-2021-44228" in (
        compiled.params.values()
    )


def test_upsert_prevents_older_score_overwrite() -> None:
    session = Mock(
        spec=Session,
    )

    repository = SqlAlchemyEPSSScoreRepository(
        session=session,
    )

    repository.upsert_many(
        {
            "CVE-2021-44228": (
                _build_snapshot()
            ),
        }
    )

    statement = (
        session.execute.call_args.args[0]
    )

    compiled = statement.compile(
        dialect=postgresql.dialect(),
    )

    sql = " ".join(
        str(
            compiled
        )
        .upper()
        .split()
    )

    assert "WHERE" in sql
    assert (
        "EXCLUDED.SCORE_DATE >= "
        "NORMALIZED.EPSS_SCORE.SCORE_DATE"
        in sql
    )


def test_upsert_many_normalizes_cve_identifier() -> None:
    session = Mock(
        spec=Session,
    )

    repository = SqlAlchemyEPSSScoreRepository(
        session=session,
    )

    repository.upsert_many(
        {
            "  cve-2021-44228  ": (
                _build_snapshot()
            ),
        }
    )

    statement = (
        session.execute.call_args.args[0]
    )

    compiled = statement.compile(
        dialect=postgresql.dialect(),
    )

    assert "CVE-2021-44228" in (
        compiled.params.values()
    )


def test_upsert_many_rejects_conflicting_normalized_duplicates(
) -> None:
    session = Mock(
        spec=Session,
    )

    repository = SqlAlchemyEPSSScoreRepository(
        session=session,
    )

    with pytest.raises(
        ValueError,
        match=(
            "Conflicting duplicate EPSS "
            "snapshot"
        ),
    ):
        repository.upsert_many(
            {
                "CVE-2021-44228": (
                    _build_snapshot(
                        score=0.80,
                    )
                ),
                "cve-2021-44228": (
                    _build_snapshot(
                        score=0.90,
                    )
                ),
            }
        )

    session.execute.assert_not_called()
    session.flush.assert_not_called()


def test_upsert_many_deduplicates_identical_normalized_entries(
) -> None:
    session = Mock(
        spec=Session,
    )

    repository = SqlAlchemyEPSSScoreRepository(
        session=session,
    )

    snapshot = _build_snapshot()

    result = repository.upsert_many(
        {
            "CVE-2021-44228": snapshot,
            "cve-2021-44228": snapshot,
        }
    )

    assert result == 1
    session.execute.assert_called_once()
    session.flush.assert_called_once_with()


def test_upsert_many_rejects_non_mapping_value() -> None:
    session = Mock(
        spec=Session,
    )

    repository = SqlAlchemyEPSSScoreRepository(
        session=session,
    )

    with pytest.raises(
        TypeError,
        match=(
            "snapshots_by_cve must "
            "be a mapping"
        ),
    ):
        repository.upsert_many(
            [  # type: ignore[arg-type]
                (
                    "CVE-2021-44228",
                    _build_snapshot(),
                ),
            ]
        )

    session.execute.assert_not_called()


def test_upsert_many_rejects_invalid_snapshot_type() -> None:
    session = Mock(
        spec=Session,
    )

    repository = SqlAlchemyEPSSScoreRepository(
        session=session,
    )

    with pytest.raises(
        TypeError,
        match=(
            "Every value must be "
            "an EPSSSnapshot"
        ),
    ):
        repository.upsert_many(
            {
                "CVE-2021-44228": {
                    "score": 0.85,
                },
            }  # type: ignore[arg-type]
        )

    session.execute.assert_not_called()


def test_upsert_many_returns_zero_for_empty_mapping() -> None:
    session = Mock(
        spec=Session,
    )

    repository = SqlAlchemyEPSSScoreRepository(
        session=session,
    )

    result = repository.upsert_many(
        {}
    )

    assert result == 0
    session.execute.assert_not_called()
    session.flush.assert_not_called()


def test_upsert_many_splits_large_collection_into_batches(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = Mock(
        spec=Session,
    )

    repository = SqlAlchemyEPSSScoreRepository(
        session=session,
    )

    monkeypatch.setattr(
        repository,
        "UPSERT_BATCH_SIZE",
        2,
    )

    snapshots = {
        "CVE-2026-1001": _build_snapshot(),
        "CVE-2026-1002": _build_snapshot(),
        "CVE-2026-1003": _build_snapshot(),
    }

    result = repository.upsert_many(
        snapshots
    )

    assert result == 3
    assert session.execute.call_count == 2
    session.flush.assert_called_once_with()