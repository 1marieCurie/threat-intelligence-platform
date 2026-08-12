from __future__ import annotations

from pathlib import Path

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


from decimal import Decimal
from uuid import UUID

from sqlalchemy import (
    exists,
    func,
    select,
)
from sqlalchemy.orm import (
    Session,
    aliased,
)

from application.models.ml_dataset import (
    MLDatasetSnapshotSpec,
    PreparedMLURLSample,
)
from application.services.ml_url_training_projector import (
    MLURLTrainingProjector,
)
from application.services.url_feature_extractor import (
    URLFeatureExtractor,
)
from application.services.url_group_key_resolver import (
    URLGroupKeyResolver,
)
from infrastructure.persistence.models.canonical_web import (
    CanonicalWebIndicatorModel,
    CanonicalWebIndicatorObservationModel,
)
from infrastructure.persistence.models.normalized_http_archive import (
    HTTPArchivePageModel,
)
from infrastructure.persistence.sqlalchemy import (
    create_ingestion_engine,
    create_session_factory,
)
from infrastructure.persistence.sqlalchemy.ml_dataset import (
    SqlAlchemyMLDatasetStore,
)


TARGET_PER_CLASS = 29_925

WRITE_SIZE = 500

HTTP_ARCHIVE_SNAPSHOT = (
    "http-archive-2026-07-01-mobile-secondary"
)

DATASET_NAME = (
    "url_multiclass"
)

DATASET_VERSION = (
    "2026-08-12-v1"
)


def _prepare_sample(
    *,
    canonical_value: str,
    value_hash: str,
    hostname: str,
    canonicalization_version: int,
    source: str,
    label_code: str,
    observed_at,
    canonical_web_indicator_id: (
        UUID | None
    ),
    source_metadata: dict[str, object],
    extractor: URLFeatureExtractor,
    projector: MLURLTrainingProjector,
    group_resolver: URLGroupKeyResolver,
) -> PreparedMLURLSample:
    features = extractor.extract(
        canonical_value
    )

    group_key = group_resolver.resolve(
        hostname
    )

    model_value = projector.project(
        canonical_value
    )

    return PreparedMLURLSample(
        value_hash=value_hash,
        hostname=hostname,
        canonicalization_version=(
            canonicalization_version
        ),
        projection_version=(
            projector.VERSION
        ),
        model_value=model_value,
        feature_set_version=(
            features.feature_set_version
        ),
        features=features.to_mapping(),
        source=source,
        source_metadata=source_metadata,
        label_code=label_code,
        label_source=source,
        confidence=Decimal(
            "0.9000"
            if label_code == "benign"
            else "1.0000"
        ),
        group_key=group_key,
        observed_at=observed_at,
        canonical_web_indicator_id=(
            canonical_web_indicator_id
        ),
    )


def _persist(
    *,
    store: SqlAlchemyMLDatasetStore,
    dataset_id: UUID,
    samples: list[
        PreparedMLURLSample
    ],
) -> None:
    for start in range(
        0,
        len(samples),
        WRITE_SIZE,
    ):
        store.persist_batch(
            dataset_id=dataset_id,
            samples=samples[
                start:
                start + WRITE_SIZE
            ],
        )


def _load_benign(
    session: Session,
    *,
    extractor: URLFeatureExtractor,
    projector: MLURLTrainingProjector,
    group_resolver: URLGroupKeyResolver,
) -> list[
    PreparedMLURLSample
]:
    threat_observation = aliased(
        CanonicalWebIndicatorObservationModel
    )

    threat_indicator = aliased(
        CanonicalWebIndicatorModel
    )

    known_threat = exists(
        select(1)
        .select_from(
            threat_indicator
        )
        .join(
            threat_observation,
            threat_observation.indicator_id
            == threat_indicator.id,
        )
        .where(
            threat_indicator
            .canonicalization_version
            == HTTPArchivePageModel
            .canonicalization_version,
            threat_indicator.value_hash
            == HTTPArchivePageModel.value_hash,
            threat_observation.source.in_(
                (
                    "phishtank",
                    "urlhaus",
                )
            ),
        )
    )

    rows = (
        session.execute(
            select(
                HTTPArchivePageModel
                .canonical_value,
                HTTPArchivePageModel
                .value_hash,
                HTTPArchivePageModel
                .hostname,
                HTTPArchivePageModel
                .canonicalization_version,
                HTTPArchivePageModel
                .source_rank,
                HTTPArchivePageModel
                .observed_at,
            )
            .where(
                HTTPArchivePageModel
                .source_snapshot
                == HTTP_ARCHIVE_SNAPSHOT,
                HTTPArchivePageModel
                .source_rank
                <= 100_000,
                ~known_threat,
            )
            .order_by(
                HTTPArchivePageModel
                .value_hash
                .asc()
            )
            .limit(
                TARGET_PER_CLASS
            )
        )
        .tuples()
        .all()
    )

    if (
        len(rows)
        != TARGET_PER_CLASS
    ):
        raise RuntimeError(
            "Not enough benign samples"
        )

    return [
        _prepare_sample(
            canonical_value=canonical_value,
            value_hash=value_hash,
            hostname=hostname,
            canonicalization_version=(
                canonicalization_version
            ),
            source="http_archive",
            label_code="benign",
            observed_at=observed_at,
            canonical_web_indicator_id=None,
            source_metadata={
                "source_snapshot": (
                    HTTP_ARCHIVE_SNAPSHOT
                ),
                "source_rank": (
                    source_rank
                ),
            },
            extractor=extractor,
            projector=projector,
            group_resolver=group_resolver,
        )
        for (
            canonical_value,
            value_hash,
            hostname,
            canonicalization_version,
            source_rank,
            observed_at,
        ) in rows
    ]


def _load_threat(
    session: Session,
    *,
    source: str,
    label_code: str,
    other_source: str,
    extractor: URLFeatureExtractor,
    projector: MLURLTrainingProjector,
    group_resolver: URLGroupKeyResolver,
) -> list[
    PreparedMLURLSample
]:
    source_observation = aliased(
        CanonicalWebIndicatorObservationModel
    )

    other_observation = aliased(
        CanonicalWebIndicatorObservationModel
    )

    time_observation = aliased(
        CanonicalWebIndicatorObservationModel
    )

    has_source = exists(
        select(1)
        .select_from(
            source_observation
        )
        .where(
            source_observation.indicator_id
            == CanonicalWebIndicatorModel.id,
            source_observation.source
            == source,
        )
    )

    has_other_source = exists(
        select(1)
        .select_from(
            other_observation
        )
        .where(
            other_observation.indicator_id
            == CanonicalWebIndicatorModel.id,
            other_observation.source
            == other_source,
        )
    )

    first_observed_at = (
        select(
            func.min(
                time_observation.observed_at
            )
        )
        .where(
            time_observation.indicator_id
            == CanonicalWebIndicatorModel.id,
            time_observation.source
            == source,
        )
        .scalar_subquery()
    )

    rows = (
        session.execute(
            select(
                CanonicalWebIndicatorModel.id,
                CanonicalWebIndicatorModel
                .canonical_value,
                CanonicalWebIndicatorModel
                .value_hash,
                CanonicalWebIndicatorModel
                .hostname,
                CanonicalWebIndicatorModel
                .canonicalization_version,
                first_observed_at.label(
                    "observed_at"
                ),
            )
            .where(
                has_source,
                ~has_other_source,
            )
            .order_by(
                CanonicalWebIndicatorModel
                .value_hash
                .asc()
            )
            .limit(
                TARGET_PER_CLASS
            )
        )
        .tuples()
        .all()
    )

    if (
        len(rows)
        != TARGET_PER_CLASS
    ):
        raise RuntimeError(
            f"Not enough {label_code} samples"
        )

    samples: list[
        PreparedMLURLSample
    ] = []

    for (
        indicator_id,
        canonical_value,
        value_hash,
        hostname,
        canonicalization_version,
        observed_at,
    ) in rows:
        if observed_at is None:
            raise RuntimeError(
                "Threat observation date missing"
            )

        samples.append(
            _prepare_sample(
                canonical_value=(
                    canonical_value
                ),
                value_hash=value_hash,
                hostname=hostname,
                canonicalization_version=(
                    canonicalization_version
                ),
                source=source,
                label_code=label_code,
                observed_at=observed_at,
                canonical_web_indicator_id=(
                    indicator_id
                ),
                source_metadata={
                    "canonical_source": (
                        source
                    ),
                },
                extractor=extractor,
                projector=projector,
                group_resolver=(
                    group_resolver
                ),
            )
        )

    return samples


def main() -> int:
    engine = create_ingestion_engine()

    try:
        session_factory = (
            create_session_factory(
                engine
            )
        )

        extractor = (
            URLFeatureExtractor()
        )

        projector = (
            MLURLTrainingProjector()
        )

        group_resolver = (
            URLGroupKeyResolver()
        )

        store = SqlAlchemyMLDatasetStore(
            session_factory=(
                session_factory
            )
        )

        spec = MLDatasetSnapshotSpec(
            name=DATASET_NAME,
            version=DATASET_VERSION,
            projection_version=(
                projector.VERSION
            ),
            feature_set_version=(
                extractor.VERSION
            ),
            class_targets={
                "benign": TARGET_PER_CLASS,
                "phishing": TARGET_PER_CLASS,
                "malware": TARGET_PER_CLASS,
            },
            label_mapping={
                "benign": 0,
                "phishing": 1,
                "malware": 2,
            },
            selection_config={
                "selection": (
                    "value_hash_ascending"
                ),
                "target_per_class": (
                    TARGET_PER_CLASS
                ),
                "group_key_version": (
                    group_resolver.VERSION
                ),
                "temporal_fields_used_as_features": (
                    False
                ),
            },
            source_manifest={
                "benign": (
                    HTTP_ARCHIVE_SNAPSHOT
                ),
                "phishing": "phishtank",
                "malware": "urlhaus",
            },
        )

        dataset_id = (
            store.ensure_draft_snapshot(
                spec=spec
            )
        )

        with (
            session_factory()
            as session
        ):
            benign = _load_benign(
                session,
                extractor=extractor,
                projector=projector,
                group_resolver=(
                    group_resolver
                ),
            )

            phishing = _load_threat(
                session,
                source="phishtank",
                label_code="phishing",
                other_source="urlhaus",
                extractor=extractor,
                projector=projector,
                group_resolver=(
                    group_resolver
                ),
            )

            malware = _load_threat(
                session,
                source="urlhaus",
                label_code="malware",
                other_source="phishtank",
                extractor=extractor,
                projector=projector,
                group_resolver=(
                    group_resolver
                ),
            )

        print(
            "Prepared: "
            f"benign={len(benign)}, "
            f"phishing={len(phishing)}, "
            f"malware={len(malware)}"
        )

        _persist(
            store=store,
            dataset_id=dataset_id,
            samples=benign,
        )

        _persist(
            store=store,
            dataset_id=dataset_id,
            samples=phishing,
        )

        _persist(
            store=store,
            dataset_id=dataset_id,
            samples=malware,
        )

        print(
            "ML dataset persisted: "
            f"dataset_id={dataset_id}"
        )

        return 0

    finally:
        engine.dispose()


if __name__ == "__main__":
    raise SystemExit(
        main()
    )