from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime, timezone
from uuid import UUID, uuid4

import pytest

from application.models.ml_dataset import (
    BenignURLCandidate,
    MLDatasetBatchPersistResult,
    MLDatasetSnapshotSpec,
    PreparedMLURLSample,
)
from application.models.url_features import (
    URLFeatureVector,
)
from application.ports.outbound.ml_dataset import (
    MLURLIdentityKey,
)
from application.services.benign_dataset_selection_service import (
    BenignDatasetSelectionService,
)
from application.services.canonical_url_normalizer import (
    CanonicalURLNormalizer,
)
from application.services.ml_url_training_projector import (
    MLURLTrainingProjector,
)
from application.services.url_feature_extractor import (
    URLFeatureExtractor,
)


SOURCE_SNAPSHOT = (
    "http-archive-2026-07-01-mobile-secondary"
)


class RecordingMLDatasetStore:
    def __init__(
        self,
    ) -> None:
        self.dataset_id = uuid4()

        self.persisted_samples: list[
            PreparedMLURLSample
        ] = []

    def ensure_draft_snapshot(
        self,
        *,
        spec: MLDatasetSnapshotSpec,
    ) -> UUID:
        return self.dataset_id

    def count_members(
        self,
        *,
        dataset_id: UUID,
        label_code: str,
    ) -> int:
        return 0

    def get_member_group_counts(
        self,
        *,
        dataset_id: UUID,
        label_code: str,
    ) -> dict[str, int]:
        return {}

    def get_member_identity_keys(
        self,
        *,
        dataset_id: UUID,
        label_code: str,
    ) -> set[
        MLURLIdentityKey
    ]:
        return set()

    def persist_benign_batch(
        self,
        *,
        dataset_id: UUID,
        samples: Sequence[
            PreparedMLURLSample
        ],
    ) -> MLDatasetBatchPersistResult:
        self.persisted_samples.extend(
            samples
        )

        return MLDatasetBatchPersistResult(
            inserted_samples=len(
                samples
            ),
            inserted_members=len(
                samples
            ),
        )


class EmptyThreatIdentityReader:
    def find_existing_identity_keys(
        self,
        identities: Sequence[
            MLURLIdentityKey
        ],
    ) -> set[
        MLURLIdentityKey
    ]:
        return set()


def _snapshot_spec(
    *,
    extractor: URLFeatureExtractor,
    projector: MLURLTrainingProjector,
) -> MLDatasetSnapshotSpec:
    return MLDatasetSnapshotSpec(
        name="benign_pool",
        version="test-feature-vector-v1",
        projection_version=(
            projector.VERSION
        ),
        feature_set_version=(
            extractor.VERSION
        ),
        class_targets={
            "benign": 1,
        },
        label_mapping={
            "benign": 0,
            "phishing": 1,
            "malware": 2,
        },
        selection_config={
            "test": True,
        },
        source_manifest={
            "source_snapshot": (
                SOURCE_SNAPSHOT
            ),
        },
    )


def test_benign_sample_contains_only_frozen_features(
) -> None:
    store = RecordingMLDatasetStore()

    extractor = URLFeatureExtractor()
    projector = MLURLTrainingProjector()

    service = BenignDatasetSelectionService(
        store=store,
        threat_identity_reader=(
            EmptyThreatIdentityReader()
        ),
        normalizer=(
            CanonicalURLNormalizer()
        ),
        feature_extractor=extractor,
        projector=projector,
        snapshot_spec=_snapshot_spec(
            extractor=extractor,
            projector=projector,
        ),
        expected_source_snapshot=(
            SOURCE_SNAPSHOT
        ),
        target_size=1,
        batch_size=1,
        max_source_rank=100_000,
    )

    result = service.run(
        [
            BenignURLCandidate(
                url=(
                    "https://www.example.com/"
                    "products/item-123"
                    "?page=2"
                ),
                registered_domain=(
                    "example.com"
                ),
                source_rank=10_000,
                source_snapshot=(
                    SOURCE_SNAPSHOT
                ),
                observed_at=datetime(
                    2026,
                    7,
                    1,
                    tzinfo=timezone.utc,
                ),
            )
        ]
    )

    assert result.target_reached is True
    assert result.inserted_members == 1

    assert len(
        store.persisted_samples
    ) == 1

    sample = (
        store.persisted_samples[0]
    )

    assert (
        sample.feature_set_version
        == extractor.VERSION
    )

    assert (
        tuple(sample.features)
        == URLFeatureVector.FEATURE_NAMES
    )

    assert (
        len(sample.features)
        == 13
    )

    assert all(
        isinstance(
            value,
            (int, float),
        )
        and not isinstance(
            value,
            bool,
        )
        for value
        in sample.features.values()
    )

    excluded_names = {
        "path_length",
        "query_length",
        "fragment_length",
        "query_parameter_count",
        "has_ip_address",
        "has_https",
        "has_non_default_port",
        "has_punycode",
        "has_percent_encoding",
    }

    assert (
        excluded_names
        .isdisjoint(
            sample.features
        )
    )


def test_rejects_snapshot_feature_version_mismatch(
) -> None:
    extractor = URLFeatureExtractor()
    projector = MLURLTrainingProjector()

    invalid_spec = MLDatasetSnapshotSpec(
        name="benign_pool",
        version="test-invalid-version",
        projection_version=(
            projector.VERSION
        ),
        feature_set_version=(
            "unexpected-version"
        ),
        class_targets={
            "benign": 1,
        },
        label_mapping={
            "benign": 0,
            "phishing": 1,
            "malware": 2,
        },
        selection_config={},
        source_manifest={},
    )

    with pytest.raises(
        ValueError,
        match=(
            "snapshot feature set version "
            "does not match extractor version"
        ),
    ):
        BenignDatasetSelectionService(
            store=RecordingMLDatasetStore(),
            threat_identity_reader=(
                EmptyThreatIdentityReader()
            ),
            normalizer=(
                CanonicalURLNormalizer()
            ),
            feature_extractor=extractor,
            projector=projector,
            snapshot_spec=invalid_spec,
            expected_source_snapshot=(
                SOURCE_SNAPSHOT
            ),
            target_size=1,
        )