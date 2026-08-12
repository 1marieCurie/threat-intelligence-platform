from __future__ import annotations

from collections.abc import Sequence
from uuid import UUID, uuid4

from sqlalchemy import (
    func,
    select,
    tuple_,
)
from sqlalchemy.dialects.postgresql import (
    insert as pg_insert,
)
from sqlalchemy.orm import (
    Session,
    sessionmaker,
)

from application.models.ml_dataset import (
    MLDatasetBatchPersistResult,
    MLDatasetSnapshotSpec,
    PreparedMLURLSample,
)
from application.ports.outbound.ml_dataset import (
    MLURLIdentityKey,
)
from infrastructure.persistence.models.canonical_web import (
    CanonicalWebIndicatorModel,
)
from infrastructure.persistence.models.ml import (
    MLDatasetMemberModel,
    MLDatasetSnapshotModel,
    MLURLFeatureVectorModel,
    MLURLProjectionModel,
    MLURLSampleLabelModel,
    MLURLSampleModel,
)


class MLDatasetConfigurationConflict(
    RuntimeError
):
    pass


class MLDatasetLabelConflict(
    RuntimeError
):
    pass


class MLDatasetProjectionConflict(
    RuntimeError
):
    pass


class MLDatasetFeatureConflict(
    RuntimeError
):
    pass


class SqlAlchemyMLThreatIdentityReader:
    def __init__(
        self,
        session_factory: sessionmaker[Session],
    ) -> None:
        self._session_factory = (
            session_factory
        )

    def find_existing_identity_keys(
        self,
        identities: Sequence[
            MLURLIdentityKey
        ],
    ) -> set[MLURLIdentityKey]:
        submitted = tuple(
            dict.fromkeys(identities)
        )

        if not submitted:
            return set()

        with self._session_factory() as session:
            rows = session.execute(
                select(
                    CanonicalWebIndicatorModel
                    .canonicalization_version,
                    CanonicalWebIndicatorModel
                    .value_hash,
                )
                .where(
                    tuple_(
                        CanonicalWebIndicatorModel
                        .canonicalization_version,
                        CanonicalWebIndicatorModel
                        .value_hash,
                    ).in_(submitted)
                )
            ).all()

        return {
            (
                row.canonicalization_version,
                row.value_hash,
            )
            for row in rows
        }


class SqlAlchemyMLDatasetStore:
    def __init__(
        self,
        session_factory: sessionmaker[Session],
    ) -> None:
        self._session_factory = (
            session_factory
        )

    def ensure_draft_snapshot(
        self,
        *,
        spec: MLDatasetSnapshotSpec,
    ) -> UUID:
        with self._session_factory() as session:
            with session.begin():
                existing = (
                    session.execute(
                        select(
                            MLDatasetSnapshotModel
                        )
                        .where(
                            MLDatasetSnapshotModel.name
                            == spec.name,
                            MLDatasetSnapshotModel.version
                            == spec.version,
                        )
                    )
                    .scalar_one_or_none()
                )

                if existing is not None:
                    self._validate_snapshot(
                        existing=existing,
                        spec=spec,
                    )

                    return existing.id

                snapshot = (
                    MLDatasetSnapshotModel(
                        id=uuid4(),
                        name=spec.name,
                        version=spec.version,
                        status="draft",
                        projection_version=(
                            spec.projection_version
                        ),
                        feature_set_version=(
                            spec.feature_set_version
                        ),
                        class_targets=dict(
                            spec.class_targets
                        ),
                        label_mapping=dict(
                            spec.label_mapping
                        ),
                        selection_config=dict(
                            spec.selection_config
                        ),
                        source_manifest=dict(
                            spec.source_manifest
                        ),
                    )
                )

                session.add(
                    snapshot
                )

                session.flush()

                return snapshot.id

    def count_members(
        self,
        *,
        dataset_id: UUID,
        label_code: str,
    ) -> int:
        with self._session_factory() as session:
            value = session.execute(
                select(
                    func.count()
                )
                .select_from(
                    MLDatasetMemberModel
                )
                .where(
                    MLDatasetMemberModel.dataset_id
                    == dataset_id,
                    MLDatasetMemberModel.label_code
                    == label_code,
                )
            ).scalar_one()

        return int(
            value
        )

    def get_member_group_counts(
        self,
        *,
        dataset_id: UUID,
        label_code: str,
    ) -> dict[str, int]:
        with self._session_factory() as session:
            rows = session.execute(
                select(
                    MLDatasetMemberModel.group_key,
                    func.count(),
                )
                .where(
                    MLDatasetMemberModel.dataset_id
                    == dataset_id,
                    MLDatasetMemberModel.label_code
                    == label_code,
                )
                .group_by(
                    MLDatasetMemberModel.group_key
                )
            ).all()

        return {
            row.group_key: int(
                row[1]
            )
            for row in rows
        }

    def get_member_identity_keys(
        self,
        *,
        dataset_id: UUID,
        label_code: str,
    ) -> set[MLURLIdentityKey]:
        with self._session_factory() as session:
            rows = session.execute(
                select(
                    MLURLSampleModel
                    .canonicalization_version,
                    MLURLSampleModel
                    .value_hash,
                )
                .join(
                    MLDatasetMemberModel,
                    MLDatasetMemberModel.sample_id
                    == MLURLSampleModel.id,
                )
                .where(
                    MLDatasetMemberModel.dataset_id
                    == dataset_id,
                    MLDatasetMemberModel.label_code
                    == label_code,
                )
            ).all()

        return {
            (
                row.canonicalization_version,
                row.value_hash,
            )
            for row in rows
        }

    def persist_benign_batch(
        self,
        *,
        dataset_id: UUID,
        samples: Sequence[
            PreparedMLURLSample
        ],
    ) -> MLDatasetBatchPersistResult:
        submitted = tuple(
            samples
        )

        if not submitted:
            return (
                MLDatasetBatchPersistResult(
                    inserted_samples=0,
                    inserted_members=0,
                )
            )

        projection_versions = {
            sample.projection_version
            for sample in submitted
        }

        feature_set_versions = {
            sample.feature_set_version
            for sample in submitted
        }

        if (
            len(projection_versions)
            != 1
        ):
            raise (
                MLDatasetConfigurationConflict(
                    "ML batch mixes "
                    "projection versions"
                )
            )

        if (
            len(feature_set_versions)
            != 1
        ):
            raise (
                MLDatasetConfigurationConflict(
                    "ML batch mixes "
                    "feature set versions"
                )
            )

        projection_version = next(
            iter(
                projection_versions
            )
        )

        feature_set_version = next(
            iter(
                feature_set_versions
            )
        )

        for sample in submitted:
            if not sample.features:
                raise MLDatasetFeatureConflict(
                    "Feature vector is empty"
                )

        identity_values = [
            (
                sample.canonicalization_version,
                sample.value_hash,
            )
            for sample in submitted
        ]

        with self._session_factory() as session:
            with session.begin():
                snapshot = (
                    session.execute(
                        select(
                            MLDatasetSnapshotModel
                        )
                        .where(
                            MLDatasetSnapshotModel.id
                            == dataset_id
                        )
                    )
                    .scalar_one()
                )

                if (
                    snapshot.status
                    != "draft"
                ):
                    raise (
                        MLDatasetConfigurationConflict(
                            "Dataset snapshot is frozen"
                        )
                    )

                if (
                    snapshot.projection_version
                    != projection_version
                ):
                    raise (
                        MLDatasetConfigurationConflict(
                            "Projection version does "
                            "not match dataset snapshot"
                        )
                    )

                if (
                    snapshot.feature_set_version
                    != feature_set_version
                ):
                    raise (
                        MLDatasetConfigurationConflict(
                            "Feature set version does "
                            "not match dataset snapshot"
                        )
                    )

                sample_values = [
                    {
                        "id": uuid4(),
                        "canonical_web_indicator_id": None,
                        "value_hash": (
                            sample.value_hash
                        ),
                        "hostname": (
                            sample.hostname
                        ),
                        "canonicalization_version": (
                            sample
                            .canonicalization_version
                        ),
                        "source": (
                            sample.source
                        ),
                        "source_metadata": dict(
                            sample.source_metadata
                        ),
                    }
                    for sample in submitted
                ]

                inserted_samples = (
                    session.execute(
                        pg_insert(
                            MLURLSampleModel
                        )
                        .values(
                            sample_values
                        )
                        .on_conflict_do_nothing(
                            index_elements=[
                                "canonicalization_version",
                                "value_hash",
                            ]
                        )
                        .returning(
                            MLURLSampleModel.id
                        )
                    )
                    .scalars()
                    .all()
                )

                stored_rows = (
                    session.execute(
                        select(
                            MLURLSampleModel.id,
                            MLURLSampleModel
                            .canonicalization_version,
                            MLURLSampleModel
                            .value_hash,
                        )
                        .where(
                            tuple_(
                                MLURLSampleModel
                                .canonicalization_version,
                                MLURLSampleModel
                                .value_hash,
                            ).in_(
                                identity_values
                            )
                        )
                    )
                    .all()
                )

                ids_by_identity = {
                    (
                        row.canonicalization_version,
                        row.value_hash,
                    ): row.id
                    for row in stored_rows
                }

                if (
                    len(
                        ids_by_identity
                    )
                    != len(
                        set(
                            identity_values
                        )
                    )
                ):
                    raise RuntimeError(
                        "Unable to resolve all "
                        "ML URL samples"
                    )

                sample_ids = tuple(
                    ids_by_identity.values()
                )

                conflicts = (
                    session.execute(
                        select(
                            MLURLSampleLabelModel
                            .sample_id,
                            MLURLSampleLabelModel
                            .label_code,
                        )
                        .where(
                            MLURLSampleLabelModel
                            .sample_id.in_(
                                sample_ids
                            ),
                            MLURLSampleLabelModel
                            .label_code
                            != "benign",
                        )
                    )
                    .all()
                )

                if conflicts:
                    raise (
                        MLDatasetLabelConflict(
                            "ML sample already has "
                            "a non-benign label"
                        )
                    )

                existing_projections = {
                    row.sample_id: (
                        row.model_value
                    )
                    for row in session.execute(
                        select(
                            MLURLProjectionModel
                            .sample_id,
                            MLURLProjectionModel
                            .model_value,
                        )
                        .where(
                            MLURLProjectionModel
                            .sample_id.in_(
                                sample_ids
                            ),
                            MLURLProjectionModel
                            .projection_version
                            == projection_version,
                        )
                    ).all()
                }

                existing_features = {
                    row.sample_id: dict(
                        row.features
                    )
                    for row in session.execute(
                        select(
                            MLURLFeatureVectorModel
                            .sample_id,
                            MLURLFeatureVectorModel
                            .features,
                        )
                        .where(
                            MLURLFeatureVectorModel
                            .sample_id.in_(
                                sample_ids
                            ),
                            MLURLFeatureVectorModel
                            .feature_set_version
                            == feature_set_version,
                        )
                    ).all()
                }

                projection_values = []
                feature_values = []

                for sample in submitted:
                    identity = (
                        sample
                        .canonicalization_version,
                        sample.value_hash,
                    )

                    sample_id = (
                        ids_by_identity[
                            identity
                        ]
                    )

                    existing_projection = (
                        existing_projections.get(
                            sample_id
                        )
                    )

                    if (
                        existing_projection
                        is not None
                        and existing_projection
                        != sample.model_value
                    ):
                        raise (
                            MLDatasetProjectionConflict(
                                "Projection is not "
                                "deterministic"
                            )
                        )

                    existing_feature_vector = (
                        existing_features.get(
                            sample_id
                        )
                    )

                    supplied_features = dict(
                        sample.features
                    )

                    if (
                        existing_feature_vector
                        is not None
                        and existing_feature_vector
                        != supplied_features
                    ):
                        raise (
                            MLDatasetFeatureConflict(
                                "Feature extraction is "
                                "not deterministic"
                            )
                        )

                    projection_values.append(
                        {
                            "sample_id": (
                                sample_id
                            ),
                            "projection_version": (
                                sample
                                .projection_version
                            ),
                            "model_value": (
                                sample.model_value
                            ),
                        }
                    )

                    feature_values.append(
                        {
                            "sample_id": (
                                sample_id
                            ),
                            "feature_set_version": (
                                sample
                                .feature_set_version
                            ),
                            "features": (
                                supplied_features
                            ),
                        }
                    )

                session.execute(
                    pg_insert(
                        MLURLProjectionModel
                    )
                    .values(
                        projection_values
                    )
                    .on_conflict_do_nothing(
                        index_elements=[
                            "sample_id",
                            "projection_version",
                        ]
                    )
                )

                session.execute(
                    pg_insert(
                        MLURLFeatureVectorModel
                    )
                    .values(
                        feature_values
                    )
                    .on_conflict_do_nothing(
                        index_elements=[
                            "sample_id",
                            "feature_set_version",
                        ]
                    )
                )

                # Relecture après les INSERT.
                #
                # Elle protège également contre un conflit
                # concurrent qui serait apparu entre la
                # première lecture et ON CONFLICT DO NOTHING.
                persisted_projections = {
                    row.sample_id: (
                        row.model_value
                    )
                    for row in session.execute(
                        select(
                            MLURLProjectionModel
                            .sample_id,
                            MLURLProjectionModel
                            .model_value,
                        )
                        .where(
                            MLURLProjectionModel
                            .sample_id.in_(
                                sample_ids
                            ),
                            MLURLProjectionModel
                            .projection_version
                            == projection_version,
                        )
                    ).all()
                }

                persisted_features = {
                    row.sample_id: dict(
                        row.features
                    )
                    for row in session.execute(
                        select(
                            MLURLFeatureVectorModel
                            .sample_id,
                            MLURLFeatureVectorModel
                            .features,
                        )
                        .where(
                            MLURLFeatureVectorModel
                            .sample_id.in_(
                                sample_ids
                            ),
                            MLURLFeatureVectorModel
                            .feature_set_version
                            == feature_set_version,
                        )
                    ).all()
                }

                for sample in submitted:
                    identity = (
                        sample
                        .canonicalization_version,
                        sample.value_hash,
                    )

                    sample_id = (
                        ids_by_identity[
                            identity
                        ]
                    )

                    if (
                        persisted_projections.get(
                            sample_id
                        )
                        != sample.model_value
                    ):
                        raise (
                            MLDatasetProjectionConflict(
                                "Projection is not "
                                "deterministic"
                            )
                        )

                    if (
                        persisted_features.get(
                            sample_id
                        )
                        != dict(
                            sample.features
                        )
                    ):
                        raise (
                            MLDatasetFeatureConflict(
                                "Feature extraction is "
                                "not deterministic"
                            )
                        )

                label_values = []
                member_values = []

                for sample in submitted:
                    identity = (
                        sample
                        .canonicalization_version,
                        sample.value_hash,
                    )

                    sample_id = (
                        ids_by_identity[
                            identity
                        ]
                    )

                    label_values.append(
                        {
                            "id": uuid4(),
                            "sample_id": (
                                sample_id
                            ),
                            "label_code": (
                                sample.label_code
                            ),
                            "label_source": (
                                sample.label_source
                            ),
                            "confidence": (
                                sample.confidence
                            ),
                            "observed_at": (
                                sample.observed_at
                            ),
                        }
                    )

                    member_values.append(
                        {
                            "dataset_id": (
                                dataset_id
                            ),
                            "sample_id": (
                                sample_id
                            ),
                            "label_code": (
                                sample.label_code
                            ),
                            "split": None,
                            "group_key": (
                                sample.group_key
                            ),
                        }
                    )

                session.execute(
                    pg_insert(
                        MLURLSampleLabelModel
                    )
                    .values(
                        label_values
                    )
                    .on_conflict_do_nothing(
                        index_elements=[
                            "sample_id",
                            "label_code",
                            "label_source",
                        ]
                    )
                )

                inserted_members = (
                    session.execute(
                        pg_insert(
                            MLDatasetMemberModel
                        )
                        .values(
                            member_values
                        )
                        .on_conflict_do_nothing(
                            index_elements=[
                                "dataset_id",
                                "sample_id",
                            ]
                        )
                        .returning(
                            MLDatasetMemberModel
                            .sample_id
                        )
                    )
                    .scalars()
                    .all()
                )

        return (
            MLDatasetBatchPersistResult(
                inserted_samples=len(
                    inserted_samples
                ),
                inserted_members=len(
                    inserted_members
                ),
            )
        )

    @staticmethod
    def _validate_snapshot(
        *,
        existing: MLDatasetSnapshotModel,
        spec: MLDatasetSnapshotSpec,
    ) -> None:
        if (
            existing.status
            != "draft"
        ):
            raise (
                MLDatasetConfigurationConflict(
                    "Dataset snapshot is frozen"
                )
            )

        expected = (
            existing.projection_version,
            existing.feature_set_version,
            existing.class_targets,
            existing.label_mapping,
            existing.selection_config,
            existing.source_manifest,
        )

        supplied = (
            spec.projection_version,
            spec.feature_set_version,
            spec.class_targets,
            spec.label_mapping,
            spec.selection_config,
            spec.source_manifest,
        )

        if expected != supplied:
            raise (
                MLDatasetConfigurationConflict(
                    "Dataset snapshot configuration "
                    "does not match"
                )
            )