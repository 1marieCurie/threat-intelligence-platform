from __future__ import annotations
from decimal import Decimal

import os
from collections.abc import Iterator
from dataclasses import (
    dataclass,
    field,
    replace,
)
from datetime import (
    UTC,
    datetime,
)
from pathlib import Path
from uuid import (
    UUID,
    uuid4,
)

from dotenv import load_dotenv


PROJECT_ROOT = (
    Path(__file__)
    .resolve()
    .parents[2]
)

load_dotenv(
    dotenv_path=PROJECT_ROOT / ".env",
    override=False,
)


import pytest
from sqlalchemy import (
    create_engine,
    delete,
    func,
    select,
    text,
)
from sqlalchemy.engine import Engine
from sqlalchemy.orm import (
    Session,
    sessionmaker,
)

from application.models.ml_dataset import (
    MLDatasetSnapshotSpec,
    PreparedMLURLSample,
)
from application.models.url_features import (
    URLFeatureVector,
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
from infrastructure.persistence.models.ml import (
    MLDatasetMemberModel,
    MLDatasetSnapshotModel,
    MLURLFeatureVectorModel,
    MLURLProjectionModel,
    MLURLSampleLabelModel,
    MLURLSampleModel,
)
from infrastructure.persistence.sqlalchemy import (
    create_ingestion_engine,
    create_session_factory,
)
from infrastructure.persistence.sqlalchemy.ml_dataset import (
    MLDatasetFeatureConflict,
    SqlAlchemyMLDatasetStore,
)


pytestmark = pytest.mark.integration


OBSERVED_AT = datetime(
    2026,
    7,
    1,
    tzinfo=UTC,
)


@dataclass(
    slots=True,
)
class DatabaseContext:
    owner_session_factory: (
        sessionmaker[Session]
    )

    ingestion_session_factory: (
        sessionmaker[Session]
    )

    dataset_ids: set[UUID] = field(
        default_factory=set
    )

    value_hashes: set[str] = field(
        default_factory=set
    )

    def track_dataset(
        self,
        dataset_id: UUID,
    ) -> None:
        self.dataset_ids.add(
            dataset_id
        )

    def track_sample(
        self,
        sample: PreparedMLURLSample,
    ) -> None:
        self.value_hashes.add(
            sample.value_hash
        )


def _owner_engine() -> Engine:
    database_url = os.environ.get(
        "MIGRATION_DATABASE_URL"
    )

    if not database_url:
        raise RuntimeError(
            "MIGRATION_DATABASE_URL "
            "is not defined"
        )

    return create_engine(
        database_url,
        pool_pre_ping=True,
    )


def _owner_session_factory(
    engine: Engine,
) -> sessionmaker[Session]:
    return sessionmaker(
        bind=engine,
        class_=Session,
        autoflush=False,
        expire_on_commit=False,
    )


def _cleanup(
    context: DatabaseContext,
) -> None:
    if (
        not context.dataset_ids
        and not context.value_hashes
    ):
        return

    with (
        context.owner_session_factory()
        as session
    ):
        session.execute(
            text(
                "SET ROLE threat_intel_owner"
            )
        )

        # Supprimer d'abord les snapshots.
        # Les memberships associés sont supprimés
        # par ON DELETE CASCADE.
        if context.dataset_ids:
            session.execute(
                delete(
                    MLDatasetSnapshotModel
                ).where(
                    MLDatasetSnapshotModel.id.in_(
                        context.dataset_ids
                    )
                )
            )

        # Projection, features et labels sont
        # supprimés avec le sample par CASCADE.
        if context.value_hashes:
            session.execute(
                delete(
                    MLURLSampleModel
                ).where(
                    MLURLSampleModel.value_hash.in_(
                        context.value_hashes
                    )
                )
            )

        session.commit()


@pytest.fixture
def database_context(
) -> Iterator[DatabaseContext]:
    owner_engine = (
        _owner_engine()
    )

    ingestion_engine: Engine | None = None

    context: DatabaseContext | None = None

    try:
        ingestion_engine = (
            create_ingestion_engine()
        )

        context = DatabaseContext(
            owner_session_factory=(
                _owner_session_factory(
                    owner_engine
                )
            ),
            ingestion_session_factory=(
                create_session_factory(
                    ingestion_engine
                )
            ),
        )

        yield context

    finally:
        try:
            if context is not None:
                _cleanup(
                    context
                )

        finally:
            if ingestion_engine is not None:
                ingestion_engine.dispose()

            owner_engine.dispose()


def _snapshot_spec(
    *,
    run_id: str,
) -> MLDatasetSnapshotSpec:
    extractor = (
        URLFeatureExtractor()
    )

    projector = (
        MLURLTrainingProjector()
    )

    return MLDatasetSnapshotSpec(
        name=(
            "ml_feature_vector_integration"
        ),
        version=(
            f"integration-{run_id}"
        ),
        projection_version=(
            projector.VERSION
        ),
        feature_set_version=(
            extractor.VERSION
        ),
        class_targets={
            "benign": 10,
        },
        label_mapping={
            "benign": 0,
            "phishing": 1,
            "malware": 2,
        },
        selection_config={
            "integration_test": True,
        },
        source_manifest={
            "test_run_id": run_id,
        },
    )


def _prepared_sample(
    *,
    token: str,
) -> PreparedMLURLSample:
    normalizer = (
        CanonicalURLNormalizer()
    )

    extractor = (
        URLFeatureExtractor()
    )

    projector = (
        MLURLTrainingProjector()
    )

    canonical_identity = (
        normalizer.normalize(
            (
                "https://"
                f"mltest-{token}.example.test/"
                "download/item-123"
                "?page=456"
            )
        )
    )

    feature_vector = (
        extractor.extract(
            canonical_identity.canonical_value
        )
    )

    model_value = (
        projector.project(
            canonical_identity.canonical_value
        )
    )

    return PreparedMLURLSample(
        value_hash=(
            canonical_identity.value_hash
        ),
        hostname=(
            canonical_identity.hostname
        ),
        canonicalization_version=(
            canonical_identity
            .canonicalization_version
        ),
        projection_version=(
            projector.VERSION
        ),
        model_value=model_value,
        feature_set_version=(
            feature_vector
            .feature_set_version
        ),
        features=(
            feature_vector.to_mapping()
        ),
        source="http_archive",
        source_metadata={
            "registered_domain": (
                "example.test"
            ),
            "source_rank": 10_000,
            "source_snapshot": (
                "integration-test"
            ),
        },
        label_code="benign",
        label_source=(
            "http_archive_selection_v1"
        ),
        confidence=Decimal("0.9000"),
        group_key="example.test",
        observed_at=OBSERVED_AT,
    )


def _set_owner_role(
    session: Session,
) -> None:
    session.execute(
        text(
            "SET ROLE threat_intel_owner"
        )
    )


def test_persists_complete_ml_sample_atomically(
    database_context: DatabaseContext,
) -> None:
    run_id = (
        uuid4().hex
    )

    store = (
        SqlAlchemyMLDatasetStore(
            session_factory=(
                database_context
                .ingestion_session_factory
            )
        )
    )

    spec = _snapshot_spec(
        run_id=run_id
    )

    dataset_id = (
        store.ensure_draft_snapshot(
            spec=spec
        )
    )

    database_context.track_dataset(
        dataset_id
    )

    sample = _prepared_sample(
        token=run_id
    )

    database_context.track_sample(
        sample
    )

    first_result = (
        store.persist_benign_batch(
            dataset_id=dataset_id,
            samples=[
                sample,
            ],
        )
    )

    assert (
        first_result.inserted_samples
        == 1
    )

    assert (
        first_result.inserted_members
        == 1
    )

    # Deuxième passage :
    # l'opération doit être idempotente.
    second_result = (
        store.persist_benign_batch(
            dataset_id=dataset_id,
            samples=[
                sample,
            ],
        )
    )

    assert (
        second_result.inserted_samples
        == 0
    )

    assert (
        second_result.inserted_members
        == 0
    )

    with (
        database_context
        .owner_session_factory()
        as session
    ):
        _set_owner_role(
            session
        )

        stored_sample = (
            session.execute(
                select(
                    MLURLSampleModel
                ).where(
                    MLURLSampleModel.value_hash
                    == sample.value_hash
                )
            )
            .scalar_one()
        )

        stored_projection = (
            session.execute(
                select(
                    MLURLProjectionModel
                ).where(
                    MLURLProjectionModel.sample_id
                    == stored_sample.id,
                    MLURLProjectionModel
                    .projection_version
                    == sample.projection_version,
                )
            )
            .scalar_one()
        )

        stored_features = (
            session.execute(
                select(
                    MLURLFeatureVectorModel
                ).where(
                    MLURLFeatureVectorModel.sample_id
                    == stored_sample.id,
                    MLURLFeatureVectorModel
                    .feature_set_version
                    == sample.feature_set_version,
                )
            )
            .scalar_one()
        )

        stored_label = (
            session.execute(
                select(
                    MLURLSampleLabelModel
                ).where(
                    MLURLSampleLabelModel.sample_id
                    == stored_sample.id,
                    MLURLSampleLabelModel.label_code
                    == "benign",
                )
            )
            .scalar_one()
        )

        stored_member = (
            session.execute(
                select(
                    MLDatasetMemberModel
                ).where(
                    MLDatasetMemberModel.dataset_id
                    == dataset_id,
                    MLDatasetMemberModel.sample_id
                    == stored_sample.id,
                )
            )
            .scalar_one()
        )

        stored_snapshot = (
            session.execute(
                select(
                    MLDatasetSnapshotModel
                ).where(
                    MLDatasetSnapshotModel.id
                    == dataset_id
                )
            )
            .scalar_one()
        )

        assert (
            stored_projection.model_value
            == sample.model_value
        )

        assert (
            stored_features.feature_set_version
            == sample.feature_set_version
        )

        assert (
            stored_features.features
            == sample.features
        )

        assert (
            set(
                stored_features.features
            )
            == set(
                URLFeatureVector.FEATURE_NAMES
            )
        )

        assert (
            len(
                stored_features.features
            )
            == 13
        )

        assert (
            stored_label.label_code
            == "benign"
        )

        assert (
            stored_member.label_code
            == "benign"
        )

        assert (
            stored_member.split
            is None
        )

        assert (
            stored_snapshot.projection_version
            == sample.projection_version
        )

        assert (
            stored_snapshot.feature_set_version
            == sample.feature_set_version
        )


def test_feature_conflict_rolls_back_entire_batch(
    database_context: DatabaseContext,
) -> None:
    run_id = (
        uuid4().hex
    )

    store = (
        SqlAlchemyMLDatasetStore(
            session_factory=(
                database_context
                .ingestion_session_factory
            )
        )
    )

    dataset_id = (
        store.ensure_draft_snapshot(
            spec=_snapshot_spec(
                run_id=run_id
            )
        )
    )

    database_context.track_dataset(
        dataset_id
    )

    existing_sample = (
        _prepared_sample(
            token=(
                f"{run_id[:20]}a"
            )
        )
    )

    database_context.track_sample(
        existing_sample
    )

    initial_result = (
        store.persist_benign_batch(
            dataset_id=dataset_id,
            samples=[
                existing_sample,
            ],
        )
    )

    assert (
        initial_result.inserted_members
        == 1
    )

    new_sample = (
        _prepared_sample(
            token=(
                f"{run_id[:20]}b"
            )
        )
    )

    database_context.track_sample(
        new_sample
    )

    conflicting_features = dict(
        existing_sample.features
    )

    conflicting_features[
        "url_length"
    ] = (
        int(
            conflicting_features[
                "url_length"
            ]
        )
        + 1
    )

    conflicting_sample = replace(
        existing_sample,
        features=(
            conflicting_features
        ),
    )

    with pytest.raises(
        MLDatasetFeatureConflict,
        match=(
            "Feature extraction is "
            "not deterministic"
        ),
    ) as error:
        store.persist_benign_batch(
            dataset_id=dataset_id,
            samples=[
                # Celui-ci est inséré au début de
                # la transaction...
                new_sample,

                # ...puis ce conflit doit provoquer
                # le rollback du batch complet.
                conflicting_sample,
            ],
        )

    # Sécurité :
    # aucune donnée URL ne doit apparaître
    # dans le message d'erreur.
    assert (
        "https://"
        not in str(
            error.value
        )
    )

    with (
        database_context
        .owner_session_factory()
        as session
    ):
        _set_owner_role(
            session
        )

        # La création de new_sample doit avoir
        # été annulée par le rollback.
        rolled_back_sample = (
            session.execute(
                select(
                    MLURLSampleModel.id
                ).where(
                    MLURLSampleModel.value_hash
                    == new_sample.value_hash
                )
            )
            .scalar_one_or_none()
        )

        assert (
            rolled_back_sample
            is None
        )

        original_row = (
            session.execute(
                select(
                    MLURLSampleModel
                ).where(
                    MLURLSampleModel.value_hash
                    == existing_sample.value_hash
                )
            )
            .scalar_one()
        )

        original_features = (
            session.execute(
                select(
                    MLURLFeatureVectorModel
                    .features
                ).where(
                    MLURLFeatureVectorModel.sample_id
                    == original_row.id,
                    MLURLFeatureVectorModel
                    .feature_set_version
                    == existing_sample
                    .feature_set_version,
                )
            )
            .scalar_one()
        )

        assert (
            original_features
            == existing_sample.features
        )

        member_count = (
            session.execute(
                select(
                    func.count()
                )
                .select_from(
                    MLDatasetMemberModel
                )
                .where(
                    MLDatasetMemberModel.dataset_id
                    == dataset_id
                )
            )
            .scalar_one()
        )

        assert (
            member_count
            == 1
        )