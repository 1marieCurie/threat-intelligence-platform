from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from uuid import UUID

from application.models.url_features import (
    URLFeatureValue,
)


@dataclass(
    frozen=True,
    slots=True,
)
class BenignURLCandidate:
    """
    Candidat benign provenant d'un snapshot HTTP Archive.

    L'URL originale reste uniquement en mémoire pendant
    la préparation et ne doit jamais être journalisée.
    """

    url: str
    registered_domain: str
    source_rank: int
    source_snapshot: str
    observed_at: datetime


@dataclass(
    frozen=True,
    slots=True,
)
class PreparedMLURLSample:
    """
    Échantillon prêt à être persisté dans le schéma ML.

    model_value contient la projection privacy-safe utilisée
    ultérieurement pour l'entraînement.

    features contient uniquement le Feature Set numérique
    explicitement autorisé par URLFeatureVector.
    """

    value_hash: str
    hostname: str
    canonicalization_version: int

    projection_version: str
    model_value: str

    feature_set_version: str
    features: dict[
        str,
        URLFeatureValue,
    ]

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
    feature_set_version: str

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