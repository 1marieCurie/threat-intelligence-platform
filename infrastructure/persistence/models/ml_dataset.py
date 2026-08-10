from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from uuid import UUID


@dataclass(
    frozen=True,
    slots=True,
)
class BenignURLCandidate:
    url: str
    registered_domain: str
    tranco_rank: int
    crux_present: bool
    crawl_id: str


@dataclass(
    frozen=True,
    slots=True,
)
class PreparedMLURLSample:
    value_hash: str
    hostname: str
    canonicalization_version: int

    projection_version: str
    model_value: str

    source: str
    source_metadata: dict[str, object]

    label_code: str
    label_source: str
    confidence: Decimal

    group_key: str
    observed_at: datetime


@dataclass(
    frozen=True,
    slots=True,
)
class MLDatasetSnapshotSpec:
    name: str
    version: str
    projection_version: str

    class_targets: dict[str, object]
    label_mapping: dict[str, object]

    selection_config: dict[str, object]
    source_manifest: dict[str, object]


@dataclass(
    frozen=True,
    slots=True,
)
class MLDatasetBatchPersistResult:
    inserted_samples: int
    inserted_members: int


@dataclass(
    frozen=True,
    slots=True,
)
class BenignDatasetBuildResult:
    dataset_id: UUID

    candidates_read: int
    candidates_normalized: int

    normalization_rejected: int
    source_rejected: int
    duplicate_rejected: int
    threat_rejected: int
    domain_quota_rejected: int

    starting_members: int
    inserted_members: int
    final_members: int

    target_size: int
    target_reached: bool