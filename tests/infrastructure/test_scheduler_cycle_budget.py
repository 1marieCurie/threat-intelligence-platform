from __future__ import annotations

from types import SimpleNamespace

from infrastructure.scheduler.refresh_stages import (
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
                "No fake result"
            )

        return self.results.pop(0)


def _ingestion(
    *,
    received,
    persisted,
    complete,
):
    return SimpleNamespace(
        records_received=received,
        records_persisted=persisted,
        pagination_complete=complete,
    )


def _normalization():
    return SimpleNamespace(
        claimed=200,
        normalized=195,
        already_normalized=3,
        failed=2,
    )


def _canonical():
    return SimpleNamespace(
        records_read=195,
        source_exhausted=True,
        max_batches_reached=False,
        canonical_created=180,
        canonical_updated=10,
        canonical_persisted=190,
    )


def test_github_cycle_budget_is_not_a_failure():
    ingestion_job = FakeJob(
        [
            _ingestion(
                received=100,
                persisted=100,
                complete=False,
            ),
            _ingestion(
                received=100,
                persisted=100,
                complete=False,
            ),
        ]
    )

    normalization_job = FakeJob(
        [
            _normalization()
        ]
    )

    canonical_job = FakeJob(
        [
            _canonical()
        ]
    )

    stage = GitHubAdvisoryRefreshStage(
        ingestion_job=ingestion_job,
        normalization_job=(
            normalization_job
        ),
        canonical_job=canonical_job,
        max_pages=100,
        cycle_page_budget=2,
        retry_delays_seconds=(),
    )

    result = stage.run()

    assert ingestion_job.calls == 2

    assert (
        normalization_job.calls
        == 1
    )

    assert canonical_job.calls == 1

    assert result.changed is True

    assert (
        result.metrics.limit_reached
        is True
    )

    assert (
        result.metrics.pages_processed
        == 2
    )

    assert (
        result.metrics.records_received
        == 200
    )

    assert (
        result.metrics.records_persisted
        == 200
    )

    assert (
        result.metrics.normalized
        == 195
    )

    assert (
        result.metrics.normalization_failed
        == 2
    )

    assert (
        result.metrics.canonical_created
        == 180
    )

    assert (
        result.metrics.canonical_updated
        == 10
    )

    assert (
        result.metrics.canonical_persisted
        == 190
    )