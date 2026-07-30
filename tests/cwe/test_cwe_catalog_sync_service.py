from __future__ import annotations

from collections.abc import Iterable
from types import TracebackType
from typing import Any, Self

import pytest

from application.ports.outbound.cwe_catalog_sync_unit_of_work import (
    CWEWeaknessBatchWriter,
)
from application.ports.outbound.cwe_reference_repository import (
    VulnerabilityCWEReferenceRepository,
)
from application.services.cwe_catalog_sync_service import (
    CWECatalogSyncResult,
    CWECatalogSyncService,
)
from domain.cwe_weakness import CWEWeakness


class FakeClient:
    def __init__(
        self,
        *,
        responses: list[
            dict[str, Any]
        ],
    ) -> None:
        self.responses = list(
            responses
        )

        self.version_calls = 0

        self.weakness_calls: list[
            list[str | int]
        ] = []

    def fetch_version(
        self,
    ) -> dict[str, Any]:
        self.version_calls += 1

        return {
            "ContentVersion": "4.20",
            "ContentDate": "2026-04-30",
        }

    def fetch_weaknesses(
        self,
        cwe_ids: Iterable[str | int],
    ) -> dict[str, Any]:
        self.weakness_calls.append(
            list(
                cwe_ids
            )
        )

        if not self.responses:
            raise AssertionError(
                "No fake CWE response configured"
            )

        return self.responses.pop(0)


class FakeReferenceRepository:
    def __init__(
        self,
        values: list[str],
    ) -> None:
        self.values = list(
            values
        )

        self.limits: list[int] = []

    def list_distinct_ids(
        self,
        *,
        limit: int,
    ) -> list[str]:
        self.limits.append(
            limit
        )

        return self.values[
            :limit
        ]


class FakeWritableRepository:
    def __init__(
        self,
        *,
        existing: list[CWEWeakness] | None = None,
    ) -> None:
        self.existing = list(
            existing or []
        )

        self.saved: list[
            list[CWEWeakness]
        ] = []

    def find_many_by_ids(
        self,
        cwe_ids: Iterable[str],
    ) -> list[CWEWeakness]:
        requested_ids = list(
            cwe_ids
        )

        existing_by_id = {
            weakness.id: weakness
            for weakness in self.existing
        }

        return [
            existing_by_id[cwe_id]
            for cwe_id in requested_ids
            if cwe_id in existing_by_id
        ]

    def upsert_many(
        self,
        weaknesses: Iterable[CWEWeakness],
    ) -> int:
        values = list(
            weaknesses
        )

        self.saved.append(
            values
        )

        return len(
            values
        )

class FakeUnitOfWork:
    """
    Faux Unit of Work limité au contrat CWE.

    Les annotations utilisent directement les ports attendus afin
    que Pylance valide le typage structurel.
    """

    def __init__(
        self,
        cwe_ids: list[str],
        *,
        existing: list[CWEWeakness] | None = None,
    ) -> None:
        self.vulnerability_cwe_references: (
            VulnerabilityCWEReferenceRepository
        ) = FakeReferenceRepository(
            cwe_ids
        )

        self.cwe_weaknesses: (
            CWEWeaknessBatchWriter
        ) = FakeWritableRepository()
        
        self.cwe_weaknesses = (
            FakeWritableRepository(
                existing=existing
            )
        )

        self.commit_count = 0
        self.enter_count = 0
        self.exit_count = 0

    def __enter__(
        self,
    ) -> Self:
        self.enter_count += 1

        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.exit_count += 1

    def commit(
        self,
    ) -> None:
        self.commit_count += 1


def _payload(
    *ids: str,
) -> dict[str, Any]:
    return {
        "Weaknesses": [
            {
                "ID": cwe_id,
                "Name": (
                    f"Weakness {cwe_id}"
                ),
                "Description": (
                    f"Description {cwe_id}"
                ),
            }
            for cwe_id in ids
        ],
    }


def test_synchronize_referenced_in_batches(
) -> None:
    client = FakeClient(
        responses=[
            _payload(
                "79",
                "89",
            ),
            _payload(
                "502",
            ),
        ]
    )

    unit_of_work = FakeUnitOfWork(
        [
            "CWE-79",
            "CWE-89",
            "CWE-502",
        ]
    )

    service = CWECatalogSyncService(
        client=client,
        unit_of_work=unit_of_work,
        batch_size=2,
    )

    result = (
        service.synchronize_referenced()
    )

    assert isinstance(
        result,
        CWECatalogSyncResult,
    )

    assert result.catalog_version == "4.20"
    assert result.catalog_date == "2026-04-30"
    assert result.requested_ids == 3
    assert result.fetched_weaknesses == 3
    assert result.persisted_weaknesses == 3
    assert result.batches == 2
    assert result.missing_ids == ()

    assert client.weakness_calls == [
        [
            "CWE-79",
            "CWE-89",
        ],
        [
            "CWE-502",
        ],
    ]

    assert unit_of_work.commit_count == 2

    # Une entrée initiale pour la lecture des références,
    # puis une transaction par lot persisté.
    assert unit_of_work.enter_count == 4
    assert unit_of_work.exit_count == 4


def test_missing_cwe_is_reported(
) -> None:
    client = FakeClient(
        responses=[
            _payload(
                "79",
            ),
        ]
    )

    unit_of_work = FakeUnitOfWork(
        [
            "CWE-79",
            "CWE-999",
        ]
    )

    service = CWECatalogSyncService(
        client=client,
        unit_of_work=unit_of_work,
    )

    result = (
        service.synchronize_referenced()
    )

    assert result.missing_ids == (
        "CWE-999",
    )

    assert result.fetched_weaknesses == 1
    assert result.persisted_weaknesses == 1
    assert unit_of_work.commit_count == 1


def test_empty_reference_collection_skips_network(
) -> None:
    client = FakeClient(
        responses=[]
    )

    unit_of_work = FakeUnitOfWork(
        []
    )

    service = CWECatalogSyncService(
        client=client,
        unit_of_work=unit_of_work,
    )

    result = (
        service.synchronize_referenced()
    )

    assert result.requested_ids == 0
    assert result.fetched_weaknesses == 0
    assert result.persisted_weaknesses == 0
    assert result.batches == 0

    assert client.version_calls == 0
    assert client.weakness_calls == []
    assert unit_of_work.commit_count == 0

    # Seule la lecture initiale des références ouvre le UoW.
    assert unit_of_work.enter_count == 1
    assert unit_of_work.exit_count == 1


def test_unexpected_cwe_is_rejected(
) -> None:
    client = FakeClient(
        responses=[
            _payload(
                "89",
            ),
        ]
    )

    unit_of_work = FakeUnitOfWork(
        [
            "CWE-79",
        ]
    )

    service = CWECatalogSyncService(
        client=client,
        unit_of_work=unit_of_work,
    )

    with pytest.raises(
        ValueError,
        match=(
            "unexpected CWE identifiers"
        ),
    ):
        service.synchronize_referenced()

    assert unit_of_work.commit_count == 0


def test_referenced_identifier_limit_is_bounded(
) -> None:
    client = FakeClient(
        responses=[]
    )

    unit_of_work = FakeUnitOfWork(
        [
            "CWE-1",
            "CWE-2",
            "CWE-3",
        ]
    )

    service = CWECatalogSyncService(
        client=client,
        unit_of_work=unit_of_work,
        max_cwe_ids=2,
    )

    with pytest.raises(
        RuntimeError,
        match=(
            "identifier limit was exceeded"
        ),
    ):
        service.synchronize_referenced()

    assert client.version_calls == 0
    assert client.weakness_calls == []


@pytest.mark.parametrize(
    "batch_size",
    [
        0,
        -1,
        51,
    ],
)
def test_invalid_batch_size_is_rejected(
    batch_size: int,
) -> None:
    with pytest.raises(
        ValueError,
    ):
        CWECatalogSyncService(
            client=FakeClient(
                responses=[]
            ),
            unit_of_work=FakeUnitOfWork(
                []
            ),
            batch_size=batch_size,
        )


@pytest.mark.parametrize(
    "batch_size",
    [
        True,
        1.5,
        "50",
    ],
)
def test_invalid_batch_size_type_is_rejected(
    batch_size: object,
) -> None:
    with pytest.raises(
        TypeError,
    ):
        CWECatalogSyncService(
            client=FakeClient(
                responses=[]
            ),
            unit_of_work=FakeUnitOfWork(
                []
            ),
            batch_size=batch_size,  # type: ignore[arg-type]
        )


@pytest.mark.parametrize(
    "max_cwe_ids",
    [
        0,
        -1,
    ],
)
def test_invalid_max_cwe_ids_is_rejected(
    max_cwe_ids: int,
) -> None:
    with pytest.raises(
        ValueError,
    ):
        CWECatalogSyncService(
            client=FakeClient(
                responses=[]
            ),
            unit_of_work=FakeUnitOfWork(
                []
            ),
            max_cwe_ids=max_cwe_ids,
        )


@pytest.mark.parametrize(
    "max_cwe_ids",
    [
        True,
        1.5,
        "5000",
    ],
)
def test_invalid_max_cwe_ids_type_is_rejected(
    max_cwe_ids: object,
) -> None:
    with pytest.raises(
        TypeError,
    ):
        CWECatalogSyncService(
            client=FakeClient(
                responses=[]
            ),
            unit_of_work=FakeUnitOfWork(
                []
            ),
            max_cwe_ids=(
                max_cwe_ids  # type: ignore[arg-type]
            ),
        )


@pytest.mark.parametrize(
    "invalid_value",
    [
        None,
        4.20,
        {},
        [],
    ],
)
def test_invalid_catalog_version_is_rejected(
    invalid_value: Any,
) -> None:
    client = FakeClient(
        responses=[
            _payload(
                "79",
            ),
        ]
    )

    client.fetch_version = lambda: {
        "ContentVersion": invalid_value,
        "ContentDate": "2026-04-30",
    }

    service = CWECatalogSyncService(
        client=client,
        unit_of_work=FakeUnitOfWork(
            [
                "CWE-79",
            ]
        ),
    )

    if invalid_value is None:
        result = (
            service.synchronize_referenced()
        )

        assert result.catalog_version is None

    else:
        with pytest.raises(
            ValueError,
            match=(
                "ContentVersion must "
                "be a string"
            ),
        ):
            service.synchronize_referenced()

def _stored_weakness(
    cwe_id: str,
    *,
    catalog_version: str = "4.20",
    catalog_date: str = "2026-04-30",
) -> CWEWeakness:
    return CWEWeakness(
        id=cwe_id,
        name=f"Stored {cwe_id}",
        description=(
            f"Stored description {cwe_id}"
        ),
        catalog_version=catalog_version,
        catalog_date=catalog_date,
    )
    
def test_synchronize_fetches_only_missing_or_stale_entries(
) -> None:
    client = FakeClient(
        responses=[
            _payload(
                "89",
                "502",
            ),
        ]
    )

    unit_of_work = FakeUnitOfWork(
        [
            "CWE-79",
            "CWE-89",
            "CWE-502",
        ],
        existing=[
            _stored_weakness(
                "CWE-79"
            ),
            _stored_weakness(
                "CWE-89",
                catalog_version="4.19",
            ),
        ],
    )

    service = CWECatalogSyncService(
        client=client,
        unit_of_work=unit_of_work,
        batch_size=10,
    )

    result = (
        service.synchronize_referenced()
    )

    assert client.weakness_calls == [
        [
            "CWE-89",
            "CWE-502",
        ],
    ]

    assert result.requested_ids == 3

    assert (
        result.up_to_date_weaknesses
        == 1
    )

    assert result.fetched_weaknesses == 2
    assert result.persisted_weaknesses == 2
    assert result.batches == 1

    assert unit_of_work.commit_count == 1
    
def test_synchronize_skips_network_when_catalog_is_current(
) -> None:
    client = FakeClient(
        responses=[]
    )

    unit_of_work = FakeUnitOfWork(
        [
            "CWE-79",
            "CWE-89",
        ],
        existing=[
            _stored_weakness(
                "CWE-79"
            ),
            _stored_weakness(
                "CWE-89"
            ),
        ],
    )

    service = CWECatalogSyncService(
        client=client,
        unit_of_work=unit_of_work,
    )

    result = (
        service.synchronize_referenced()
    )

    assert client.version_calls == 1
    assert client.weakness_calls == []

    assert result.requested_ids == 2

    assert (
        result.up_to_date_weaknesses
        == 2
    )

    assert result.fetched_weaknesses == 0
    assert result.persisted_weaknesses == 0
    assert result.batches == 0

    assert unit_of_work.commit_count == 0