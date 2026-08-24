from __future__ import annotations

from types import SimpleNamespace

import pytest
import requests

from infrastructure.adapters.outbound.github_advisory_connector import (
    GitHubAdvisoryConnectorError,
)
from infrastructure.scheduler.refresh_stages import (
    CisaKevRefreshStage,
    EPSSRefreshStage,
    GitHubAdvisoryRefreshStage,
)


def _ingestion_result(
    *,
    persisted: int,
    complete: bool,
):
    return SimpleNamespace(
        records_persisted=persisted,
        pagination_complete=complete,
    )


def _normalization_result(
    *,
    claimed: int,
):
    return SimpleNamespace(
        claimed=claimed,
    )


def _canonical_result(
    *,
    records_read: int,
    source_exhausted: bool = True,
    max_batches_reached: bool = False,
):
    return SimpleNamespace(
        records_read=records_read,
        source_exhausted=(
            source_exhausted
        ),
        max_batches_reached=(
            max_batches_reached
        ),
    )


def _github_error(
    cause: BaseException,
) -> GitHubAdvisoryConnectorError:
    error = GitHubAdvisoryConnectorError(
        "GitHub test failure"
    )

    error.__cause__ = cause

    return error


def _http_error(
    *,
    status_code: int,
    retry_after: str | None = None,
    remaining: str | None = None,
    text: str = "",
) -> requests.HTTPError:
    response = requests.Response()

    response.status_code = ( # type: ignore
        status_code
    )

    response._content = (
        text.encode("utf-8")
    )

    if retry_after is not None:
        response.headers[
            "Retry-After"
        ] = retry_after

    if remaining is not None:
        response.headers[
            "X-RateLimit-Remaining"
        ] = remaining

    return requests.HTTPError(
        f"HTTP {status_code}",
        response=response,
    )


class FakeJob:
    def __init__(
        self,
        results,
        *,
        calls=None,
        name=None,
    ):
        self.results = list(
            results
        )

        self.calls = calls
        self.name = name

    def run(
        self,
    ):
        if self.calls is not None:
            self.calls.append(
                self.name
            )

        if not self.results:
            raise RuntimeError(
                "No fake result available"
            )

        value = self.results.pop(0)

        if isinstance(
            value,
            BaseException,
        ):
            raise value

        return value


def test_cisa_stage_runs_complete_pipeline():
    calls = []

    stage = CisaKevRefreshStage(
        ingestion_job=FakeJob(
            [
                _ingestion_result(
                    persisted=3,
                    complete=True,
                )
            ],
            calls=calls,
            name="ingestion",
        ),
        normalization_job=FakeJob(
            [
                _normalization_result(
                    claimed=3,
                )
            ],
            calls=calls,
            name="normalization",
        ),
        canonical_job=FakeJob(
            [
                _canonical_result(
                    records_read=3,
                )
            ],
            calls=calls,
            name="canonical",
        ),
    )

    result = stage.run()

    assert calls == [
        "ingestion",
        "normalization",
        "canonical",
    ]

    assert result.changed is True
    assert result.processed_count == 3


def test_cisa_stage_detects_unchanged_snapshot():
    stage = CisaKevRefreshStage(
        ingestion_job=FakeJob(
            [
                _ingestion_result(
                    persisted=0,
                    complete=True,
                )
            ]
        ),
        normalization_job=FakeJob(
            [
                _normalization_result(
                    claimed=0,
                )
            ]
        ),
        canonical_job=FakeJob(
            [
                _canonical_result(
                    records_read=50,
                )
            ]
        ),
    )

    result = stage.run()

    assert result.changed is False
    assert result.processed_count == 50


def test_cisa_rejects_incomplete_snapshot():
    stage = CisaKevRefreshStage(
        ingestion_job=FakeJob(
            [
                _ingestion_result(
                    persisted=0,
                    complete=False,
                )
            ]
        ),
        normalization_job=FakeJob(
            []
        ),
        canonical_job=FakeJob(
            []
        ),
    )

    with pytest.raises(
        RuntimeError,
        match=(
            "did not return a "
            "complete snapshot"
        ),
    ):
        stage.run()


def test_github_stage_consumes_all_pages():
    ingestion_job = FakeJob(
        [
            _ingestion_result(
                persisted=2,
                complete=False,
            ),
            _ingestion_result(
                persisted=1,
                complete=False,
            ),
            _ingestion_result(
                persisted=0,
                complete=True,
            ),
        ]
    )

    stage = GitHubAdvisoryRefreshStage(
        ingestion_job=ingestion_job,
        normalization_job=FakeJob(
            [
                _normalization_result(
                    claimed=3,
                )
            ]
        ),
        canonical_job=FakeJob(
            [
                _canonical_result(
                    records_read=3,
                )
            ]
        ),
        max_pages=5,
    )

    result = stage.run()

    assert result.changed is True
    assert result.processed_count == 3
    assert ingestion_job.results == []


def test_github_stage_rejects_incomplete_pagination():
    stage = GitHubAdvisoryRefreshStage(
        ingestion_job=FakeJob(
            [
                _ingestion_result(
                    persisted=1,
                    complete=False,
                ),
                _ingestion_result(
                    persisted=1,
                    complete=False,
                ),
            ]
        ),
        normalization_job=FakeJob(
            []
        ),
        canonical_job=FakeJob(
            []
        ),
        max_pages=2,
    )

    with pytest.raises(
        RuntimeError,
        match="reached max_pages",
    ):
        stage.run()


def test_github_timeout_is_retried_then_succeeds():
    sleeps = []

    ingestion_job = FakeJob(
        [
            _github_error(
                requests.Timeout()
            ),
            _ingestion_result(
                persisted=1,
                complete=True,
            ),
        ]
    )

    stage = GitHubAdvisoryRefreshStage(
        ingestion_job=ingestion_job,
        normalization_job=FakeJob(
            [
                _normalization_result(
                    claimed=1,
                )
            ]
        ),
        canonical_job=FakeJob(
            [
                _canonical_result(
                    records_read=1,
                )
            ]
        ),
        retry_delays_seconds=(
            2.0,
            5.0,
            10.0,
        ),
        sleeper=sleeps.append,
    )

    result = stage.run()

    assert sleeps == [
        2.0,
    ]

    assert result.changed is True


def test_github_timeout_retries_are_bounded():
    sleeps = []

    ingestion_job = FakeJob(
        [
            _github_error(
                requests.Timeout()
            ),
            _github_error(
                requests.Timeout()
            ),
            _github_error(
                requests.Timeout()
            ),
            _github_error(
                requests.Timeout()
            ),
        ]
    )

    stage = GitHubAdvisoryRefreshStage(
        ingestion_job=ingestion_job,
        normalization_job=FakeJob(
            []
        ),
        canonical_job=FakeJob(
            []
        ),
        retry_delays_seconds=(
            2.0,
            5.0,
            10.0,
        ),
        sleeper=sleeps.append,
    )

    with pytest.raises(
        GitHubAdvisoryConnectorError,
    ):
        stage.run()

    assert sleeps == [
        2.0,
        5.0,
        10.0,
    ]


def test_github_401_is_not_retried():
    sleeps = []

    ingestion_job = FakeJob(
        [
            _github_error(
                _http_error(
                    status_code=401,
                )
            ),
            _ingestion_result(
                persisted=1,
                complete=True,
            ),
        ]
    )

    stage = GitHubAdvisoryRefreshStage(
        ingestion_job=ingestion_job,
        normalization_job=FakeJob(
            []
        ),
        canonical_job=FakeJob(
            []
        ),
        sleeper=sleeps.append,
    )

    with pytest.raises(
        GitHubAdvisoryConnectorError,
    ):
        stage.run()

    assert sleeps == []

    assert len(
        ingestion_job.results
    ) == 1


def test_github_429_respects_short_retry_after():
    sleeps = []

    ingestion_job = FakeJob(
        [
            _github_error(
                _http_error(
                    status_code=429,
                    retry_after="3",
                )
            ),
            _ingestion_result(
                persisted=1,
                complete=True,
            ),
        ]
    )

    stage = GitHubAdvisoryRefreshStage(
        ingestion_job=ingestion_job,
        normalization_job=FakeJob(
            [
                _normalization_result(
                    claimed=1,
                )
            ]
        ),
        canonical_job=FakeJob(
            [
                _canonical_result(
                    records_read=1,
                )
            ]
        ),
        sleeper=sleeps.append,
    )

    result = stage.run()

    assert sleeps == [
        3.0,
    ]

    assert result.changed is True


def test_github_long_rate_limit_does_not_block_scheduler():
    sleeps = []

    stage = GitHubAdvisoryRefreshStage(
        ingestion_job=FakeJob(
            [
                _github_error(
                    _http_error(
                        status_code=429,
                        retry_after="300",
                    )
                )
            ]
        ),
        normalization_job=FakeJob(
            []
        ),
        canonical_job=FakeJob(
            []
        ),
        sleeper=sleeps.append,
    )

    with pytest.raises(
        GitHubAdvisoryConnectorError,
    ):
        stage.run()

    assert sleeps == []


class FakeCVEReader:
    def __init__(
        self,
        pages,
    ):
        self.pages = dict(
            pages
        )

        self.calls = []

    def read_batch(
        self,
        *,
        after_cve_id,
        limit,
    ):
        self.calls.append(
            (
                after_cve_id,
                limit,
            )
        )

        return self.pages.get(
            after_cve_id,
            (),
        )


class FakeEPSSJob:
    def __init__(
        self,
        submitted_by_batch,
    ):
        self.submitted_by_batch = list(
            submitted_by_batch
        )

        self.calls = []

    def run(
        self,
        cve_ids,
    ):
        self.calls.append(
            tuple(
                cve_ids
            )
        )

        return SimpleNamespace(
            submitted_scores=(
                self
                .submitted_by_batch
                .pop(0)
            )
        )


def test_epss_stage_processes_canonical_cves_by_batch():
    reader = FakeCVEReader(
        {
            None: (
                "CVE-2024-0001",
                "CVE-2024-0002",
            ),
            "CVE-2024-0002": (
                "CVE-2024-0003",
            ),
        }
    )

    synchronization_job = (
        FakeEPSSJob(
            [
                2,
                1,
            ]
        )
    )

    stage = EPSSRefreshStage(
        cve_reader=reader,
        synchronization_job=(
            synchronization_job
        ),
        canonical_job=FakeJob(
            [
                _canonical_result(
                    records_read=3,
                )
            ]
        ),
        batch_size=2,
        max_batches=10,
    )

    result = stage.run()

    assert (
        synchronization_job.calls
        == [
            (
                "CVE-2024-0001",
                "CVE-2024-0002",
            ),
            (
                "CVE-2024-0003",
            ),
        ]
    )

    assert result.changed is True
    assert result.processed_count == 3


def test_canonical_stage_must_complete():
    stage = CisaKevRefreshStage(
        ingestion_job=FakeJob(
            [
                _ingestion_result(
                    persisted=1,
                    complete=True,
                )
            ]
        ),
        normalization_job=FakeJob(
            [
                _normalization_result(
                    claimed=1,
                )
            ]
        ),
        canonical_job=FakeJob(
            [
                _canonical_result(
                    records_read=100,
                    source_exhausted=False,
                    max_batches_reached=True,
                )
            ]
        ),
    )

    with pytest.raises(
        RuntimeError,
        match=(
            "canonical correlation "
            "did not complete"
        ),
    ):
        stage.run()