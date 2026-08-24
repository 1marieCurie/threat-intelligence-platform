from __future__ import annotations

from types import SimpleNamespace

from infrastructure.scheduler.refresh_stages import (
    CisaKevRefreshStage,
    GitHubAdvisoryRefreshStage,
)


class FakeJob:
    def __init__(
        self,
        results,
    ):
        self.results = list(
            results
        )

        self.calls = 0

    def run(
        self,
    ):
        self.calls += 1

        if not self.results:
            raise RuntimeError(
                "No fake result available"
            )

        result = (
            self.results.pop(0)
        )

        if isinstance(
            result,
            BaseException,
        ):
            raise result

        return result


def _ingestion(
    *,
    received: int,
    persisted: int,
    complete: bool = True,
):
    return SimpleNamespace(
        records_received=received,
        records_persisted=persisted,
        pagination_complete=complete,
    )


def _normalization(
    *,
    claimed: int,
    normalized: int,
    already_normalized: int = 0,
    failed: int = 0,
):
    return SimpleNamespace(
        claimed=claimed,
        normalized=normalized,
        already_normalized=(
            already_normalized
        ),
        failed=failed,
    )


def _canonical(
    *,
    records_read: int,
    created: int,
    updated: int,
    persisted: int,
):
    return SimpleNamespace(
        records_read=records_read,
        source_exhausted=True,
        max_batches_reached=False,
        canonical_created=created,
        canonical_updated=updated,
        canonical_persisted=persisted,
    )


def test_cisa_canonical_replay_does_not_mark_source_changed():
    stage = CisaKevRefreshStage(
        ingestion_job=FakeJob(
            [
                _ingestion(
                    received=1674,
                    persisted=0,
                )
            ]
        ),
        normalization_job=FakeJob(
            [
                _normalization(
                    claimed=0,
                    normalized=0,
                )
            ]
        ),
        canonical_job=FakeJob(
            [
                _canonical(
                    records_read=1695,
                    created=0,
                    updated=1674,
                    persisted=1674,
                )
            ]
        ),
    )

    result = stage.run()

    assert result.changed is False

    assert (
        result.metrics.records_persisted
        == 0
    )

    assert (
        result.metrics.normalized
        == 0
    )

    assert (
        result.metrics.canonical_updated
        == 1674
    )


def test_cisa_new_raw_data_marks_source_changed():
    stage = CisaKevRefreshStage(
        ingestion_job=FakeJob(
            [
                _ingestion(
                    received=1675,
                    persisted=1,
                )
            ]
        ),
        normalization_job=FakeJob(
            [
                _normalization(
                    claimed=1,
                    normalized=1,
                )
            ]
        ),
        canonical_job=FakeJob(
            [
                _canonical(
                    records_read=1696,
                    created=0,
                    updated=1,
                    persisted=1,
                )
            ]
        ),
    )

    result = stage.run()

    assert result.changed is True


def test_github_incremental_canonical_catchup_marks_source_changed():
    stage = (
        GitHubAdvisoryRefreshStage(
            ingestion_job=FakeJob(
                [
                    _ingestion(
                        received=100,
                        persisted=0,
                        complete=True,
                    )
                ]
            ),
            normalization_job=FakeJob(
                [
                    _normalization(
                        claimed=0,
                        normalized=0,
                    )
                ]
            ),
            canonical_job=FakeJob(
                [
                    _canonical(
                        records_read=25,
                        created=5,
                        updated=20,
                        persisted=25,
                    )
                ]
            ),
            max_pages=100,
            cycle_page_budget=5,
            retry_delays_seconds=(),
        )
    )

    result = stage.run()

    assert result.changed is True

    assert (
        result.metrics.records_persisted
        == 0
    )

    assert (
        result.metrics.normalized
        == 0
    )

    assert (
        result.metrics.canonical_records_read
        == 25
    )

    assert (
        result.metrics.canonical_created
        == 5
    )

    assert (
        result.metrics.canonical_updated
        == 20
    )


def test_github_without_any_delta_is_unchanged():
    stage = (
        GitHubAdvisoryRefreshStage(
            ingestion_job=FakeJob(
                [
                    _ingestion(
                        received=100,
                        persisted=0,
                        complete=True,
                    )
                ]
            ),
            normalization_job=FakeJob(
                [
                    _normalization(
                        claimed=0,
                        normalized=0,
                    )
                ]
            ),
            canonical_job=FakeJob(
                [
                    _canonical(
                        records_read=0,
                        created=0,
                        updated=0,
                        persisted=0,
                    )
                ]
            ),
            max_pages=100,
            cycle_page_budget=5,
            retry_delays_seconds=(),
        )
    )

    result = stage.run()

    assert result.changed is False