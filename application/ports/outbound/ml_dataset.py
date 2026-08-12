from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol
from uuid import UUID

from application.models.ml_dataset import (
    MLDatasetBatchPersistResult,
    MLDatasetSnapshotSpec,
    PreparedMLURLSample,
)


MLURLIdentityKey = tuple[int, str]


class MLDatasetStore(Protocol):
    def ensure_draft_snapshot(
        self,
        *,
        spec: MLDatasetSnapshotSpec,
    ) -> UUID:
        ...

    def count_members(
        self,
        *,
        dataset_id: UUID,
        label_code: str,
    ) -> int:
        ...

    def get_member_group_counts(
        self,
        *,
        dataset_id: UUID,
        label_code: str,
    ) -> dict[str, int]:
        ...

    def get_member_identity_keys(
        self,
        *,
        dataset_id: UUID,
        label_code: str,
    ) -> set[MLURLIdentityKey]:
        ...

    def persist_batch(
        self,
        *,
        dataset_id: UUID,
        samples: Sequence[
            PreparedMLURLSample
        ],
    ) -> MLDatasetBatchPersistResult:
        ...


class MLThreatIdentityReader(Protocol):
    def find_existing_identity_keys(
        self,
        identities: Sequence[
            MLURLIdentityKey
        ],
    ) -> set[MLURLIdentityKey]:
        ...