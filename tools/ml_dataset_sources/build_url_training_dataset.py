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


# Petit découpage uniquement pour les INSERT PostgreSQL.
# Ce n'est pas une stratégie de traitement "big data".
PERSIST_CHUNK_SIZE = 500

HTTP_ARCHIVE_SNAPSHOT = (
    "http-archive-2026-07-01-mobile-secondary"
)

# Nouveau snapshot :
# l'ancien url_multiclass/2026-08-12-v1 est partiel
# et ne doit pas servir au training.
DATASET_NAME = "url_multiclass_pool"
DATASET_VERSION = "2026-08-12-v1"


def _prepare_sample(
    *,
    canonical_value: str,
    value_hash: str,
    hostname: str,
    canonicalization_version: int,
    source: str,
    label_code: str,
    label_source: str,
    confidence: Decimal,
    observed_at,
    canonical_web_indicator_id: UUID | None,
    source_metadata: dict[str, object],
    extractor: URLFeatureExtractor,
    projector: MLURLTrainingProjector,
    group_resolver: URLGroupKeyResolver,
) -> PreparedMLURLSample:
    """
    Prépare un échantillon ML.

    Important :
    - les features sont extraites depuis l'URL canonique ;
    - la projection privacy-safe est produite ensuite ;
    - group_key est une métadonnée de split, pas une feature ;
    - observed_at est une métadonnée d'audit, pas une feature.
    """

    feature_vector = extractor.extract(
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
            feature_vector
            .feature_set_version
        ),
        features=(
            feature_vector.to_mapping()
        ),
        source=source,
        source_metadata=source_metadata,
        label_code=label_code,
        label_source=label_source,
        confidence=confidence,
        group_key=group_key,
        observed_at=observed_at,
        canonical_web_indicator_id=(
            canonical_web_indicator_id
        ),
    )


def _benign_threat_exists_expression():
    """
    Exclut du pool benign toute identité HTTP Archive
    également connue dans PhishTank ou URLhaus.
    """

    threat_indicator = aliased(
        CanonicalWebIndicatorModel
    )

    threat_observation = aliased(
        CanonicalWebIndicatorObservationModel
    )

    return exists(
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


def _threat_source_expressions(
    *,
    source: str,
    other_source: str,
):
    """
    Construit les deux conditions utilisées pour une classe
    de menace.

    Une identité présente dans PhishTank ET URLhaus est
    volontairement exclue du dataset V1.
    """

    source_observation = aliased(
        CanonicalWebIndicatorObservationModel
    )

    other_observation = aliased(
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

    return (
        has_source,
        has_other_source,
    )


def _count_benign(
    *,
    session: Session,
) -> int:
    known_threat = (
        _benign_threat_exists_expression()
    )

    value = session.execute(
        select(
            func.count()
        )
        .select_from(
            HTTPArchivePageModel
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
    ).scalar_one()

    return int(
        value
    )


def _count_threat(
    *,
    session: Session,
    source: str,
    other_source: str,
) -> int:
    (
        has_source,
        has_other_source,
    ) = _threat_source_expressions(
        source=source,
        other_source=other_source,
    )

    value = session.execute(
        select(
            func.count()
        )
        .select_from(
            CanonicalWebIndicatorModel
        )
        .where(
            has_source,
            ~has_other_source,
        )
    ).scalar_one()

    return int(
        value
    )


def _load_benign(
    *,
    session: Session,
    extractor: URLFeatureExtractor,
    projector: MLURLTrainingProjector,
    group_resolver: URLGroupKeyResolver,
) -> list[
    PreparedMLURLSample
]:
    """
    Charge tout le pool benign éligible.

    Aucun balancing et aucun sous-échantillonnage
    ne sont effectués ici.
    """

    known_threat = (
        _benign_threat_exists_expression()
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
        )
        .tuples()
        .all()
    )

    samples: list[
        PreparedMLURLSample
    ] = []

    for (
        canonical_value,
        value_hash,
        hostname,
        canonicalization_version,
        source_rank,
        observed_at,
    ) in rows:
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
                source="http_archive",
                label_code="benign",
                label_source=(
                    "http_archive"
                ),
                confidence=Decimal(
                    "0.9000"
                ),
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
                group_resolver=(
                    group_resolver
                ),
            )
        )

    return samples


def _load_threat(
    *,
    session: Session,
    source: str,
    other_source: str,
    label_code: str,
    extractor: URLFeatureExtractor,
    projector: MLURLTrainingProjector,
    group_resolver: URLGroupKeyResolver,
) -> list[
    PreparedMLURLSample
]:
    """
    Charge toutes les identités canoniques éligibles
    pour une classe de menace.

    Aucun LIMIT, sampling ou balancing n'est appliqué.

    Une identité présente dans les deux sources de menace
    est exclue comme cas ambigu.
    """

    temporal_observation = aliased(
        CanonicalWebIndicatorObservationModel
    )

    (
        has_source,
        has_other_source,
    ) = _threat_source_expressions(
        source=source,
        other_source=other_source,
    )

    first_observed_at = (
        select(
            func.min(
                temporal_observation
                .observed_at
            )
        )
        .where(
            temporal_observation.indicator_id
            == CanonicalWebIndicatorModel.id,
            temporal_observation.source
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
        )
        .tuples()
        .all()
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
                "Threat observation timestamp "
                "is missing"
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
                label_source=source,
                confidence=Decimal(
                    "1.0000"
                ),
                observed_at=observed_at,
                canonical_web_indicator_id=(
                    indicator_id
                ),
                source_metadata={
                    "canonical_source": source,
                },
                extractor=extractor,
                projector=projector,
                group_resolver=(
                    group_resolver
                ),
            )
        )

    return samples


def _persist_class(
    *,
    store: SqlAlchemyMLDatasetStore,
    dataset_id: UUID,
    label_code: str,
    expected_count: int,
    samples: list[
        PreparedMLURLSample
    ],
) -> None:
    if len(
        samples
    ) != expected_count:
        raise RuntimeError(
            f"Unexpected prepared count "
            f"for {label_code}: "
            f"{len(samples)} != "
            f"{expected_count}"
        )

    inserted_members = 0
    inserted_samples = 0

    for start in range(
        0,
        len(samples),
        PERSIST_CHUNK_SIZE,
    ):
        result = store.persist_batch(
            dataset_id=dataset_id,
            samples=samples[
                start:
                start
                + PERSIST_CHUNK_SIZE
            ],
        )

        inserted_samples += (
            result.inserted_samples
        )

        inserted_members += (
            result.inserted_members
        )

    final_count = (
        store.count_members(
            dataset_id=dataset_id,
            label_code=label_code,
        )
    )

    if (
        final_count
        != expected_count
    ):
        raise RuntimeError(
            f"Unexpected final count "
            f"for {label_code}: "
            f"{final_count} != "
            f"{expected_count}"
        )

    print(
        f"{label_code}: "
        f"members={final_count}, "
        f"inserted_samples_now="
        f"{inserted_samples}, "
        f"inserted_members_now="
        f"{inserted_members}"
    )


def main() -> int:
    engine = (
        create_ingestion_engine()
    )

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

        store = (
            SqlAlchemyMLDatasetStore(
                session_factory=(
                    session_factory
                )
            )
        )

        # Les volumes sont déterminés par les données
        # effectivement disponibles, et non par une cible
        # artificielle de balancing.
        with (
            session_factory()
            as session
        ):
            benign_count = (
                _count_benign(
                    session=session
                )
            )

            phishing_count = (
                _count_threat(
                    session=session,
                    source="phishtank",
                    other_source="urlhaus",
                )
            )

            malware_count = (
                _count_threat(
                    session=session,
                    source="urlhaus",
                    other_source="phishtank",
                )
            )

        print(
            "=== ELIGIBLE ML POOL ==="
        )
        print(
            f"benign={benign_count}"
        )
        print(
            f"phishing={phishing_count}"
        )
        print(
            f"malware={malware_count}"
        )
        print(
            "total="
            f"{(
                benign_count
                + phishing_count
                + malware_count
            )}"
        )

        snapshot_spec = (
            MLDatasetSnapshotSpec(
                name=DATASET_NAME,
                version=DATASET_VERSION,
                projection_version=(
                    projector.VERSION
                ),
                feature_set_version=(
                    extractor.VERSION
                ),
                class_targets={
                    "benign": (
                        benign_count
                    ),
                    "phishing": (
                        phishing_count
                    ),
                    "malware": (
                        malware_count
                    ),
                },
                label_mapping={
                    "benign": 0,
                    "phishing": 1,
                    "malware": 2,
                },
                selection_config={
                    "selection": (
                        "all_eligible"
                    ),
                    "balancing": (
                        "deferred_to_training"
                    ),
                    "split": (
                        "deferred_to_training"
                    ),
                    "temporal_selection": (
                        "none"
                    ),
                    "temporal_features": False,
                    "group_key_version": (
                        group_resolver.VERSION
                    ),
                    "cross_source_exact_overlap": (
                        "exclude"
                    ),
                },
                source_manifest={
                    "benign": (
                        HTTP_ARCHIVE_SNAPSHOT
                    ),
                    "phishing": (
                        "phishtank"
                    ),
                    "malware": (
                        "urlhaus"
                    ),
                },
            )
        )

        dataset_id = (
            store.ensure_draft_snapshot(
                spec=snapshot_spec
            )
        )

        print(
            f"dataset_id={dataset_id}"
        )

        # Benign
        with (
            session_factory()
            as session
        ):
            benign = _load_benign(
                session=session,
                extractor=extractor,
                projector=projector,
                group_resolver=(
                    group_resolver
                ),
            )

        print(
            "prepared benign="
            f"{len(benign)}"
        )

        _persist_class(
            store=store,
            dataset_id=dataset_id,
            label_code="benign",
            expected_count=(
                benign_count
            ),
            samples=benign,
        )

        del benign

        # Phishing
        with (
            session_factory()
            as session
        ):
            phishing = _load_threat(
                session=session,
                source="phishtank",
                other_source="urlhaus",
                label_code="phishing",
                extractor=extractor,
                projector=projector,
                group_resolver=(
                    group_resolver
                ),
            )

        print(
            "prepared phishing="
            f"{len(phishing)}"
        )

        _persist_class(
            store=store,
            dataset_id=dataset_id,
            label_code="phishing",
            expected_count=(
                phishing_count
            ),
            samples=phishing,
        )

        del phishing

        # Malware
        with (
            session_factory()
            as session
        ):
            malware = _load_threat(
                session=session,
                source="urlhaus",
                other_source="phishtank",
                label_code="malware",
                extractor=extractor,
                projector=projector,
                group_resolver=(
                    group_resolver
                ),
            )

        print(
            "prepared malware="
            f"{len(malware)}"
        )

        _persist_class(
            store=store,
            dataset_id=dataset_id,
            label_code="malware",
            expected_count=(
                malware_count
            ),
            samples=malware,
        )

        del malware

        print(
            "ML pool construction completed."
        )

        return 0

    finally:
        engine.dispose()


if __name__ == "__main__":
    raise SystemExit(
        main()
    )