from __future__ import annotations

from collections.abc import Iterable
from datetime import (
    UTC,
    datetime,
    timedelta,
)
from types import TracebackType
from typing import Self, Any
from uuid import (
    UUID,
    uuid4,
)

import pytest

from application.models.canonical_url_identity import (
    CanonicalURLIdentity,
)
from application.models.canonical_web_indicator_observation import (
    CanonicalWebIndicatorObservation,
)
from application.ports.outbound.canonical_web_indicator_repository import (
    WebIndicatorIdentityKey,
    WebIndicatorObservationKey,
)
from application.services.canonical_url_normalizer import (
    CanonicalURLNormalizer,
)
from application.services.canonical_web_indicator_correlation_service import (
    CanonicalWebCorrelationConflictError,
    CanonicalWebIndicatorCorrelationService,
)
from domain.canonical_web_indicator import (
    CanonicalWebIndicator,
)
from domain.web_indicator_observation import (
    WebIndicatorObservation,
)


NOW = datetime(
    2026,
    8,
    5,
    19,
    0,
    tzinfo=UTC,
)


class FakeCanonicalWebIndicatorRepository:
    def __init__(self) -> None:
        self.aggregates: dict[
            UUID,
            CanonicalWebIndicator,
        ] = {}

    def find_by_id(
        self,
        indicator_id: UUID,
    ) -> CanonicalWebIndicator | None:
        return self.aggregates.get(
            indicator_id
        )

    def find_many_by_ids(
        self,
        indicator_ids: Iterable[UUID],
    ) -> dict[
        UUID,
        CanonicalWebIndicator,
    ]:
        return {
            indicator_id: aggregate
            for indicator_id in indicator_ids
            if (
                aggregate
                := self.aggregates.get(
                    indicator_id
                )
            )
            is not None
        }

    def find_many_by_identities(
        self,
        identities: Iterable[
            CanonicalURLIdentity
        ],
    ) -> dict[
        WebIndicatorIdentityKey,
        CanonicalWebIndicator,
    ]:
        requested_keys = {
            (
                identity
                .canonicalization_version,
                identity.value_hash,
            )
            for identity in identities
        }

        result: dict[
            WebIndicatorIdentityKey,
            CanonicalWebIndicator,
        ] = {}

        for aggregate in (
            self.aggregates.values()
        ):
            key = (
                aggregate
                .canonicalization_version,
                aggregate.value_hash,
            )

            if key in requested_keys:
                result[key] = aggregate

        return result

    def find_many_by_observations(
        self,
        observations: Iterable[
            WebIndicatorObservation
        ],
    ) -> dict[
        WebIndicatorObservationKey,
        CanonicalWebIndicator,
    ]:
        requested_keys = {
            observation.key
            for observation in observations
        }

        result: dict[
            WebIndicatorObservationKey,
            CanonicalWebIndicator,
        ] = {}

        for aggregate in (
            self.aggregates.values()
        ):
            for observation in (
                aggregate.observations
            ):
                if (
                    observation.key
                    in requested_keys
                ):
                    result[
                        observation.key
                    ] = aggregate

        return result

    def upsert_many(
        self,
        indicators: Iterable[
            CanonicalWebIndicator
        ],
    ) -> int:
        values = tuple(
            indicators
        )

        for indicator in values:
            self.aggregates[
                indicator.id
            ] = indicator

        return len(
            {
                indicator.id
                for indicator in values
            }
        )


class FakeCanonicalWebIndicatorUnitOfWork:
    def __init__(self, repository: Any) -> None:
        self.canonical_web_indicators: Any = repository

        self.entered = 0
        self.commits = 0
        self.rollbacks = 0

    def __enter__(
        self,
    ) -> Self:
        self.entered += 1
        return self

    def __exit__(
        self,
        exception_type: type[
            BaseException
        ] | None,
        exception: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        if exception_type is not None:
            self.rollback()

    def commit(
        self,
    ) -> None:
        self.commits += 1

    def rollback(
        self,
    ) -> None:
        self.rollbacks += 1


def _canonical_observation(
    *,
    source: str,
    source_record_key: str,
    url: str,
    normalized_record_id: UUID | None = None,
    observed_at: datetime = NOW,
    source_status: str | None = "online",
    is_active: bool | None = True,
    labels: tuple[str, ...] = (),
) -> CanonicalWebIndicatorObservation:
    identity = (
        CanonicalURLNormalizer()
        .normalize(
            url
        )
    )

    observation = WebIndicatorObservation(
        source=source,
        source_record_key=(
            source_record_key
        ),
        normalized_record_id=(
            normalized_record_id
            or uuid4()
        ),
        observed_at=observed_at,
        last_observed_at=observed_at,
        normalizer_version="1.0.0",
        source_status=source_status,
        is_active=is_active,
        labels=labels,
    )

    return CanonicalWebIndicatorObservation(
        identity=identity,
        observation=observation,
    )


def _service(
    repository: (
        FakeCanonicalWebIndicatorRepository
    ),
    *,
    generated_id: UUID | None = None,
    max_observations: int = 5_000,
) -> tuple[
    CanonicalWebIndicatorCorrelationService,
    FakeCanonicalWebIndicatorUnitOfWork,
]:
    unit_of_work = (
        FakeCanonicalWebIndicatorUnitOfWork(
            repository
        )
    )

    identifier = (
        generated_id
        or uuid4()
    )

    service = (
        CanonicalWebIndicatorCorrelationService(
            unit_of_work=unit_of_work,
            uuid_factory=lambda: identifier,
            clock=lambda: NOW,
            max_observations=(
                max_observations
            ),
        )
    )

    return (
        service,
        unit_of_work,
    )


def test_correlates_two_sources_by_exact_url(
) -> None:
    repository = (
        FakeCanonicalWebIndicatorRepository()
    )

    generated_id = uuid4()

    service, unit_of_work = _service(
        repository,
        generated_id=generated_id,
    )

    result = service.correlate(
        (
            _canonical_observation(
                source="phishtank",
                source_record_key="100",
                url=(
                    "HTTPS://Example.com:443/login"
                ),
                labels=(
                    "phishing",
                ),
            ),
            _canonical_observation(
                source="urlhaus",
                source_record_key="200",
                url=(
                    "https://example.com/login"
                ),
                labels=(
                    "malware_distribution",
                ),
            ),
        )
    )

    assert result.created == 1
    assert result.updated == 0
    assert result.persisted == 1
    assert result.components_built == 1

    aggregate = result.aggregates[0]

    assert aggregate.id == generated_id

    assert aggregate.sources == (
        "phishtank",
        "urlhaus",
    )

    assert aggregate.labels == (
        "phishing",
        "malware_distribution",
    )

    assert unit_of_work.commits == 1
    assert unit_of_work.rollbacks == 0


def test_does_not_correlate_same_hostname_with_different_paths(
) -> None:
    repository = (
        FakeCanonicalWebIndicatorRepository()
    )

    generated_ids = iter(
        (
            uuid4(),
            uuid4(),
        )
    )

    unit_of_work = (
        FakeCanonicalWebIndicatorUnitOfWork(
            repository
        )
    )

    service = (
        CanonicalWebIndicatorCorrelationService(
            unit_of_work=unit_of_work,
            uuid_factory=lambda: next(
                generated_ids
            ),
            clock=lambda: NOW,
        )
    )

    result = service.correlate(
        (
            _canonical_observation(
                source="phishtank",
                source_record_key="100",
                url=(
                    "https://example.com/login"
                ),
            ),
            _canonical_observation(
                source="urlhaus",
                source_record_key="200",
                url=(
                    "https://example.com/payload"
                ),
            ),
        )
    )

    assert result.created == 2
    assert result.components_built == 2
    assert result.persisted == 2


def test_enriches_existing_indicator(
) -> None:
    repository = (
        FakeCanonicalWebIndicatorRepository()
    )

    service, _ = _service(
        repository
    )

    first_result = service.correlate(
        (
            _canonical_observation(
                source="phishtank",
                source_record_key="100",
                url=(
                    "https://example.com/login"
                ),
                labels=(
                    "phishing",
                ),
            ),
        )
    )

    aggregate_id = (
        first_result.aggregates[0].id
    )

    second_result = service.correlate(
        (
            _canonical_observation(
                source="urlhaus",
                source_record_key="200",
                url=(
                    "https://example.com/login"
                ),
                labels=(
                    "malware_distribution",
                ),
            ),
        )
    )

    assert second_result.created == 0
    assert second_result.updated == 1

    aggregate = (
        second_result.aggregates[0]
    )

    assert aggregate.id == aggregate_id
    assert len(
        aggregate.observations
    ) == 2


def test_latest_source_snapshot_replaces_state(
) -> None:
    repository = (
        FakeCanonicalWebIndicatorRepository()
    )

    service, _ = _service(
        repository
    )

    normalized_record_id = uuid4()

    service.correlate(
        (
            _canonical_observation(
                source="phishtank",
                source_record_key="100",
                url=(
                    "https://example.com/login"
                ),
                normalized_record_id=(
                    normalized_record_id
                ),
                observed_at=NOW,
                source_status="unverified",
                is_active=True,
                labels=(
                    "suspected_phishing",
                ),
            ),
        )
    )

    later_record_id = uuid4()

    result = service.correlate(
        (
            _canonical_observation(
                source="phishtank",
                source_record_key="100",
                url=(
                    "https://example.com/login"
                ),
                normalized_record_id=(
                    later_record_id
                ),
                observed_at=(
                    NOW
                    + timedelta(hours=1)
                ),
                source_status="verified",
                is_active=False,
                labels=(
                    "phishing",
                ),
            ),
        )
    )

    observation = (
        result
        .aggregates[0]
        .observations[0]
    )

    assert (
        observation.normalized_record_id
        == later_record_id
    )

    assert observation.source_status == (
        "verified"
    )

    assert observation.is_active is False

    assert observation.labels == (
        "phishing",
    )


def test_rejects_one_source_record_for_two_urls(
) -> None:
    repository = (
        FakeCanonicalWebIndicatorRepository()
    )

    service, unit_of_work = _service(
        repository
    )

    with pytest.raises(
        CanonicalWebCorrelationConflictError,
        match="several canonical",
    ):
        service.correlate(
            (
                _canonical_observation(
                    source="urlhaus",
                    source_record_key="200",
                    url=(
                        "https://example.com/a"
                    ),
                ),
                _canonical_observation(
                    source="urlhaus",
                    source_record_key="200",
                    url=(
                        "https://example.com/b"
                    ),
                ),
            )
        )

    assert unit_of_work.commits == 0


def test_rejects_moving_persisted_observation_to_another_url(
) -> None:
    repository = (
        FakeCanonicalWebIndicatorRepository()
    )

    service, unit_of_work = _service(
        repository
    )

    service.correlate(
        (
            _canonical_observation(
                source="urlhaus",
                source_record_key="200",
                url=(
                    "https://example.com/a"
                ),
            ),
        )
    )

    with pytest.raises(
        CanonicalWebCorrelationConflictError,
        match="cannot be moved",
    ):
        service.correlate(
            (
                _canonical_observation(
                    source="urlhaus",
                    source_record_key="200",
                    url=(
                        "https://example.com/b"
                    ),
                ),
            )
        )

    assert unit_of_work.commits == 1
    assert unit_of_work.rollbacks == 1


def test_empty_batch_does_not_open_transaction(
) -> None:
    repository = (
        FakeCanonicalWebIndicatorRepository()
    )

    service, unit_of_work = _service(
        repository
    )

    result = service.correlate(
        ()
    )

    assert result.persisted == 0
    assert result.aggregates == ()
    assert unit_of_work.entered == 0
    assert unit_of_work.commits == 0


def test_rejects_batch_above_configured_limit(
) -> None:
    repository = (
        FakeCanonicalWebIndicatorRepository()
    )

    service, unit_of_work = _service(
        repository,
        max_observations=1,
    )

    with pytest.raises(
        ValueError,
        match="configured limit",
    ):
        service.correlate(
            (
                _canonical_observation(
                    source="phishtank",
                    source_record_key="100",
                    url=(
                        "https://example.com/a"
                    ),
                ),
                _canonical_observation(
                    source="urlhaus",
                    source_record_key="200",
                    url=(
                        "https://example.com/b"
                    ),
                ),
            )
        )

    assert unit_of_work.entered == 0