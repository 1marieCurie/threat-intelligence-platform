from __future__ import annotations

from collections.abc import Sequence
from math import isfinite
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
from application.models.url_features import (
    URLFeatureVector,
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


class MLDatasetCanonicalIdentityConflict(
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
    ) -> set[
        MLURLIdentityKey
    ]:
        submitted = tuple(
            dict.fromkeys(
                identities
            )
        )

        if not submitted:
            return set()

        with (
            self._session_factory()
            as session
        ):
            rows = (
                session.execute(
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
                        ).in_(
                            submitted
                        )
                    )
                )
                .all()
            )

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
        with (
            self._session_factory()
            as session
        ):
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
        with (
            self._session_factory()
            as session
        ):
            value = (
                session.execute(
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
                )
                .scalar_one()
            )

        return int(
            value
        )

    def get_member_group_counts(
        self,
        *,
        dataset_id: UUID,
        label_code: str,
    ) -> dict[
        str,
        int,
    ]:
        with (
            self._session_factory()
            as session
        ):
            rows = (
                session.execute(
                    select(
                        MLDatasetMemberModel
                        .group_key,
                        func.count(),
                    )
                    .where(
                        MLDatasetMemberModel.dataset_id
                        == dataset_id,
                        MLDatasetMemberModel.label_code
                        == label_code,
                    )
                    .group_by(
                        MLDatasetMemberModel
                        .group_key
                    )
                )
                .all()
            )

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
    ) -> set[
        MLURLIdentityKey
    ]:
        with (
            self._session_factory()
            as session
        ):
            rows = (
                session.execute(
                    select(
                        MLURLSampleModel
                        .canonicalization_version,
                        MLURLSampleModel
                        .value_hash,
                    )
                    .join(
                        MLDatasetMemberModel,
                        MLDatasetMemberModel
                        .sample_id
                        == MLURLSampleModel.id,
                    )
                    .where(
                        MLDatasetMemberModel.dataset_id
                        == dataset_id,
                        MLDatasetMemberModel.label_code
                        == label_code,
                    )
                )
                .all()
            )

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
        """
        Compatibilité avec l'ancien builder benign.

        Le nouveau pipeline doit utiliser persist_batch().
        """

        if any(
            sample.label_code != "benign"
            for sample in samples
        ):
            raise MLDatasetLabelConflict(
                "Benign batch contains "
                "a non-benign label"
            )

        return self.persist_batch(
            dataset_id=dataset_id,
            samples=samples,
        )

    def persist_batch(
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

        self._validate_submitted_batch(
            submitted
        )

        projection_version = (
            submitted[0]
            .projection_version
        )

        feature_set_version = (
            submitted[0]
            .feature_set_version
        )

        label_code = (
            submitted[0]
            .label_code
        )

        identity_values = tuple(
            (
                sample
                .canonicalization_version,
                sample.value_hash,
            )
            for sample in submitted
        )

        with (
            self._session_factory()
            as session
        ):
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

                self._validate_batch_snapshot(
                    snapshot=snapshot,
                    projection_version=(
                        projection_version
                    ),
                    feature_set_version=(
                        feature_set_version
                    ),
                    label_code=label_code,
                )

                self._validate_canonical_references(
                    session=session,
                    samples=submitted,
                )

                sample_values = [
                    {
                        "id": uuid4(),
                        "canonical_web_indicator_id": (
                            sample
                            .canonical_web_indicator_id # type: ignore
                        ),
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
                            .canonical_web_indicator_id,
                            MLURLSampleModel
                            .canonicalization_version,
                            MLURLSampleModel
                            .value_hash,
                            MLURLSampleModel
                            .hostname,
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

                rows_by_identity = {
                    (
                        row.canonicalization_version,
                        row.value_hash,
                    ): row
                    for row in stored_rows
                }

                if (
                    len(
                        rows_by_identity
                    )
                    != len(
                        identity_values
                    )
                ):
                    raise RuntimeError(
                        "Unable to resolve all "
                        "ML URL samples"
                    )

                for sample in submitted:
                    identity = (
                        sample
                        .canonicalization_version,
                        sample.value_hash,
                    )

                    stored = (
                        rows_by_identity[
                            identity
                        ]
                    )

                    if (
                        stored.hostname
                        != sample.hostname
                    ):
                        raise (
                            MLDatasetConfigurationConflict(
                                "Stored ML sample "
                                "metadata is inconsistent"
                            )
                        )

                    supplied_canonical_id = (
                        sample
                        .canonical_web_indicator_id # type: ignore
                    )

                    stored_canonical_id = (
                        stored
                        .canonical_web_indicator_id
                    )

                    if (
                        supplied_canonical_id
                        is not None
                        and stored_canonical_id
                        != supplied_canonical_id
                    ):
                        raise (
                            MLDatasetCanonicalIdentityConflict(
                                "Canonical identity "
                                "does not match stored "
                                "ML sample"
                            )
                        )

                sample_ids = tuple(
                    row.id
                    for row
                    in rows_by_identity.values()
                )

                label_conflicts = (
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
                            != label_code,
                        )
                    )
                    .all()
                )

                if label_conflicts:
                    raise (
                        MLDatasetLabelConflict(
                            "ML sample already has "
                            "a conflicting label"
                        )
                    )

                member_conflicts = (
                    session.execute(
                        select(
                            MLDatasetMemberModel
                            .sample_id,
                            MLDatasetMemberModel
                            .label_code,
                        )
                        .where(
                            MLDatasetMemberModel.dataset_id
                            == dataset_id,
                            MLDatasetMemberModel
                            .sample_id.in_(
                                sample_ids
                            ),
                            MLDatasetMemberModel
                            .label_code
                            != label_code,
                        )
                    )
                    .all()
                )

                if member_conflicts:
                    raise (
                        MLDatasetLabelConflict(
                            "Dataset member already "
                            "has a conflicting label"
                        )
                    )

                existing_projections = {
                    row.sample_id: (
                        row.model_value
                    )
                    for row
                    in session.execute(
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
                    for row
                    in session.execute(
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

                projection_values: list[
                    dict[str, object]
                ] = []

                feature_values: list[
                    dict[str, object]
                ] = []

                for sample in submitted:
                    identity = (
                        sample
                        .canonicalization_version,
                        sample.value_hash,
                    )

                    sample_id = (
                        rows_by_identity[
                            identity
                        ]
                        .id
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

                    supplied_features = dict(
                        sample.features
                    )

                    existing_feature_vector = (
                        existing_features.get(
                            sample_id
                        )
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

                # Relecture après INSERT :
                # protège l'idempotence et un éventuel
                # conflit concurrent.
                persisted_projections = {
                    row.sample_id: (
                        row.model_value
                    )
                    for row
                    in session.execute(
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
                    for row
                    in session.execute(
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
                        rows_by_identity[
                            identity
                        ]
                        .id
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

                label_values: list[
                    dict[str, object]
                ] = []

                member_values: list[
                    dict[str, object]
                ] = []

                for sample in submitted:
                    identity = (
                        sample
                        .canonicalization_version,
                        sample.value_hash,
                    )

                    sample_id = (
                        rows_by_identity[
                            identity
                        ]
                        .id
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

    @classmethod
    def _validate_submitted_batch(
        cls,
        samples: tuple[
            PreparedMLURLSample,
            ...,
        ],
    ) -> None:
        projection_versions = {
            sample.projection_version
            for sample in samples
        }

        if len(
            projection_versions
        ) != 1:
            raise (
                MLDatasetConfigurationConflict(
                    "ML batch mixes "
                    "projection versions"
                )
            )

        feature_set_versions = {
            sample.feature_set_version
            for sample in samples
        }

        if len(
            feature_set_versions
        ) != 1:
            raise (
                MLDatasetConfigurationConflict(
                    "ML batch mixes "
                    "feature set versions"
                )
            )

        label_codes = {
            sample.label_code
            for sample in samples
        }

        if len(
            label_codes
        ) != 1:
            raise (
                MLDatasetConfigurationConflict(
                    "ML batch must contain "
                    "one label"
                )
            )

        identities = [
            (
                sample
                .canonicalization_version,
                sample.value_hash,
            )
            for sample in samples
        ]

        if (
            len(
                identities
            )
            != len(
                set(
                    identities
                )
            )
        ):
            raise (
                MLDatasetConfigurationConflict(
                    "ML batch contains "
                    "duplicate identities"
                )
            )

        for sample in samples:
            cls._validate_feature_mapping(
                sample.features
            )

    @staticmethod
    def _validate_feature_mapping(
        features: dict[
            str,
            int | float,
        ],
    ) -> None:
        expected_names = set(
            URLFeatureVector
            .FEATURE_NAMES
        )

        supplied_names = set(
            features
        )

        if (
            supplied_names
            != expected_names
        ):
            raise (
                MLDatasetFeatureConflict(
                    "Feature vector schema "
                    "does not match frozen "
                    "feature set"
                )
            )

        for value in features.values():
            if (
                isinstance(
                    value,
                    bool,
                )
                or not isinstance(
                    value,
                    (
                        int,
                        float,
                    ),
                )
            ):
                raise (
                    MLDatasetFeatureConflict(
                        "Feature vector contains "
                        "a non-numeric value"
                    )
                )

            try:
                finite = isfinite(
                    value
                )

            except (
                TypeError,
                OverflowError,
            ):
                finite = False

            if not finite:
                raise (
                    MLDatasetFeatureConflict(
                        "Feature vector contains "
                        "a non-finite value"
                    )
                )

    @staticmethod
    def _validate_batch_snapshot(
        *,
        snapshot: MLDatasetSnapshotModel,
        projection_version: str,
        feature_set_version: str,
        label_code: str,
    ) -> None:
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

        if (
            label_code
            not in snapshot.label_mapping
            or label_code
            not in snapshot.class_targets
        ):
            raise (
                MLDatasetConfigurationConflict(
                    "Label is not configured "
                    "for dataset snapshot"
                )
            )

    @staticmethod
    def _validate_canonical_references(
        *,
        session: Session,
        samples: tuple[
            PreparedMLURLSample,
            ...,
        ],
    ) -> None:
        canonical_ids = {
            sample
            .canonical_web_indicator_id # type: ignore
            for sample in samples
            if (
                sample
                .canonical_web_indicator_id # type: ignore
                is not None
            )
        }

        if not canonical_ids:
            return

        rows = (
            session.execute(
                select(
                    CanonicalWebIndicatorModel
                    .id,
                    CanonicalWebIndicatorModel
                    .canonicalization_version,
                    CanonicalWebIndicatorModel
                    .value_hash,
                )
                .where(
                    CanonicalWebIndicatorModel
                    .id.in_(
                        canonical_ids
                    )
                )
            )
            .all()
        )

        canonical_by_id = {
            row.id: (
                row.canonicalization_version,
                row.value_hash,
            )
            for row in rows
        }

        if (
            len(
                canonical_by_id
            )
            != len(
                canonical_ids
            )
        ):
            raise (
                MLDatasetCanonicalIdentityConflict(
                    "Canonical ML reference "
                    "does not exist"
                )
            )

        for sample in samples:
            canonical_id = (
                sample
                .canonical_web_indicator_id # type: ignore
            )

            if canonical_id is None:
                continue

            expected_identity = (
                sample
                .canonicalization_version,
                sample.value_hash,
            )

            if (
                canonical_by_id.get(
                    canonical_id
                )
                != expected_identity
            ):
                raise (
                    MLDatasetCanonicalIdentityConflict(
                        "Canonical ML reference "
                        "does not match sample "
                        "identity"
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

        if (
            expected
            != supplied
        ):
            raise (
                MLDatasetConfigurationConflict(
                    "Dataset snapshot "
                    "configuration does not match"
                )
            )