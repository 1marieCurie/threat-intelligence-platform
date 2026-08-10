from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
from datetime import datetime, timezone
from decimal import Decimal
from ipaddress import ip_address
from uuid import UUID

from application.models.ml_dataset import (
    BenignDatasetBuildResult,
    BenignURLCandidate,
    MLDatasetSnapshotSpec,
    PreparedMLURLSample,
)
from application.ports.outbound.ml_dataset import (
    MLDatasetStore,
    MLThreatIdentityReader,
    MLURLIdentityKey,
)
from application.services.canonical_url_normalizer import (
    CanonicalURLNormalizationError,
    CanonicalURLNormalizer,
)
from application.services.ml_url_training_projector import (
    MLURLTrainingProjector,
)


class BenignCandidateValidationError(ValueError):
    """
    Rejet fonctionnel d'un candidat benign.

    Les messages ne doivent jamais contenir l'URL brute.
    """


class BenignDatasetSelectionService:
    """
    Construit un pool benign distribué et reproductible.

    Principes :
    - aucun accès réseau ;
    - canonicalisation identique aux URLs CTI ;
    - exclusion des URLs déjà connues comme menaces ;
    - quota par registered domain ;
    - projection privacy-safe avant persistance ;
    - traitement en batches bornés.
    """

    LABEL_CODE = "benign"
    LABEL_SOURCE = "benign_selection_v1"

    SOURCE = "crux_tranco"

    CONFIDENCE = Decimal("0.9000")

    DEFAULT_TARGET_SIZE = 60_000
    DEFAULT_MAX_PER_DOMAIN = 4

    DEFAULT_BATCH_SIZE = 500
    MAX_BATCH_SIZE = 1_000

    DEFAULT_MAX_CANDIDATES = 120_000
    DEFAULT_MAX_TRANCO_RANK = 100_000

    def __init__(
        self,
        *,
        store: MLDatasetStore,
        threat_identity_reader: MLThreatIdentityReader,
        normalizer: CanonicalURLNormalizer,
        projector: MLURLTrainingProjector,
        snapshot_spec: MLDatasetSnapshotSpec,
        expected_source_snapshot: str,
        target_size: int = DEFAULT_TARGET_SIZE,
        max_per_domain: int = DEFAULT_MAX_PER_DOMAIN,
        batch_size: int = DEFAULT_BATCH_SIZE,
        max_candidates: int = DEFAULT_MAX_CANDIDATES,
        max_tranco_rank: int = DEFAULT_MAX_TRANCO_RANK,
    ) -> None:
        if not isinstance(
            expected_source_snapshot,
            str,
        ):
            raise TypeError(
                "expected_source_snapshot "
                "must be a string"
            )

        normalized_snapshot = (
            expected_source_snapshot.strip()
        )

        if not normalized_snapshot:
            raise ValueError(
                "expected_source_snapshot "
                "must not be empty"
            )

        self._validate_positive_integer(
            name="target_size",
            value=target_size,
        )

        self._validate_positive_integer(
            name="max_per_domain",
            value=max_per_domain,
        )

        self._validate_positive_integer(
            name="max_candidates",
            value=max_candidates,
        )

        self._validate_positive_integer(
            name="max_tranco_rank",
            value=max_tranco_rank,
        )

        self._validate_batch_size(
            batch_size
        )

        self._store = store

        self._threat_identity_reader = (
            threat_identity_reader
        )

        self._normalizer = normalizer
        self._projector = projector

        self._snapshot_spec = snapshot_spec

        self._expected_source_snapshot = (
            normalized_snapshot
        )

        self._target_size = target_size
        self._max_per_domain = max_per_domain

        self._batch_size = batch_size
        self._max_candidates = max_candidates

        self._max_tranco_rank = max_tranco_rank

    def run(
        self,
        candidates: Iterable[
            BenignURLCandidate
        ],
    ) -> BenignDatasetBuildResult:
        dataset_id = (
            self._store.ensure_draft_snapshot(
                spec=self._snapshot_spec
            )
        )

        starting_members = (
            self._store.count_members(
                dataset_id=dataset_id,
                label_code=self.LABEL_CODE,
            )
        )

        if starting_members >= self._target_size:
            return BenignDatasetBuildResult(
                dataset_id=dataset_id,
                candidates_read=0,
                candidates_normalized=0,
                normalization_rejected=0,
                source_rejected=0,
                duplicate_rejected=0,
                threat_rejected=0,
                domain_quota_rejected=0,
                starting_members=starting_members,
                inserted_members=0,
                final_members=starting_members,
                target_size=self._target_size,
                target_reached=True,
            )

        group_counts = Counter(
            self._store.get_member_group_counts(
                dataset_id=dataset_id,
                label_code=self.LABEL_CODE,
            )
        )

        existing_identity_keys = set(
            self._store.get_member_identity_keys(
                dataset_id=dataset_id,
                label_code=self.LABEL_CODE,
            )
        )

        candidates_read = 0
        candidates_normalized = 0

        normalization_rejected = 0
        source_rejected = 0
        duplicate_rejected = 0
        threat_rejected = 0
        domain_quota_rejected = 0

        inserted_members = 0

        pending: list[
            PreparedMLURLSample
        ] = []

        pending_identity_keys: set[
            MLURLIdentityKey
        ] = set()

        for candidate in candidates:
            current_members = (
                starting_members
                + inserted_members
            )

            if current_members >= self._target_size:
                break

            if candidates_read >= self._max_candidates:
                break

            candidates_read += 1

            try:
                prepared = self._prepare(
                    candidate
                )

            except CanonicalURLNormalizationError:
                normalization_rejected += 1
                continue

            except BenignCandidateValidationError:
                source_rejected += 1
                continue

            candidates_normalized += 1

            identity_key: MLURLIdentityKey = (
                prepared.canonicalization_version,
                prepared.value_hash,
            )

            if (
                identity_key in existing_identity_keys
                or identity_key in pending_identity_keys
            ):
                duplicate_rejected += 1
                continue

            pending.append(prepared)
            pending_identity_keys.add(
                identity_key
            )

            if len(pending) >= self._batch_size:
                (
                    persisted,
                    rejected_threats,
                    rejected_quota,
                ) = self._flush(
                    dataset_id=dataset_id,
                    samples=pending,
                    group_counts=group_counts,
                    existing_identity_keys=(
                        existing_identity_keys
                    ),
                    remaining_target=(
                        self._target_size
                        - starting_members
                        - inserted_members
                    ),
                )

                inserted_members += persisted

                threat_rejected += rejected_threats
                domain_quota_rejected += rejected_quota

                pending.clear()
                pending_identity_keys.clear()

        remaining_target = (
            self._target_size
            - starting_members
            - inserted_members
        )

        if pending and remaining_target > 0:
            (
                persisted,
                rejected_threats,
                rejected_quota,
            ) = self._flush(
                dataset_id=dataset_id,
                samples=pending,
                group_counts=group_counts,
                existing_identity_keys=(
                    existing_identity_keys
                ),
                remaining_target=remaining_target,
            )

            inserted_members += persisted

            threat_rejected += rejected_threats
            domain_quota_rejected += rejected_quota

        final_members = (
            starting_members
            + inserted_members
        )

        return BenignDatasetBuildResult(
            dataset_id=dataset_id,
            candidates_read=candidates_read,
            candidates_normalized=candidates_normalized,
            normalization_rejected=(
                normalization_rejected
            ),
            source_rejected=source_rejected,
            duplicate_rejected=duplicate_rejected,
            threat_rejected=threat_rejected,
            domain_quota_rejected=(
                domain_quota_rejected
            ),
            starting_members=starting_members,
            inserted_members=inserted_members,
            final_members=final_members,
            target_size=self._target_size,
            target_reached=(
                final_members
                >= self._target_size
            ),
        )

    def _prepare(
        self,
        candidate: BenignURLCandidate,
    ) -> PreparedMLURLSample:
        registered_domain = (
            self._normalize_registered_domain(
                candidate.registered_domain
            )
        )

        if (
            candidate.tranco_rank < 1
            or candidate.tranco_rank
            > self._max_tranco_rank
        ):
            raise BenignCandidateValidationError(
                "candidate Tranco rank "
                "is outside the allowed range"
            )

        if (
            candidate.source_snapshot.strip()
            != self._expected_source_snapshot
        ):
            raise BenignCandidateValidationError(
                "candidate source snapshot "
                "does not match dataset snapshot"
            )

        identity = self._normalizer.normalize(
            candidate.url
        )

        if not self._hostname_belongs_to_domain(
            hostname=identity.hostname,
            registered_domain=registered_domain,
        ):
            raise BenignCandidateValidationError(
                "candidate hostname does not "
                "belong to registered domain"
            )

        model_value = self._projector.project(
            identity.canonical_value
        )

        if (
            not isinstance(
                model_value,
                str,
            )
            or not model_value
        ):
            raise BenignCandidateValidationError(
                "URL projection is invalid"
            )

        return PreparedMLURLSample(
            value_hash=identity.value_hash,
            hostname=identity.hostname,
            canonicalization_version=(
                identity.canonicalization_version
            ),
            projection_version=(
                self._projector.VERSION
            ),
            model_value=model_value,
            source=self.SOURCE,
            source_metadata={
                "registered_domain": (
                    registered_domain
                ),
                "tranco_rank": (
                    candidate.tranco_rank
                ),
                "source_snapshot": (
                    candidate.source_snapshot
                ),
            },
            label_code=self.LABEL_CODE,
            label_source=self.LABEL_SOURCE,
            confidence=self.CONFIDENCE,
            group_key=registered_domain,
            observed_at=datetime.now(
                timezone.utc
            ),
        )

    def _flush(
        self,
        *,
        dataset_id: UUID,
        samples: list[
            PreparedMLURLSample
        ],
        group_counts: Counter[str],
        existing_identity_keys: set[
            MLURLIdentityKey
        ],
        remaining_target: int,
    ) -> tuple[
        int,
        int,
        int,
    ]:
        if (
            not samples
            or remaining_target <= 0
        ):
            return (
                0,
                0,
                0,
            )

        identities = tuple(
            (
                sample.canonicalization_version,
                sample.value_hash,
            )
            for sample in samples
        )

        threat_identity_keys = (
            self._threat_identity_reader
            .find_existing_identity_keys(
                identities
            )
        )

        accepted: list[
            PreparedMLURLSample
        ] = []

        threat_rejected = 0
        domain_quota_rejected = 0

        accepted_identity_keys: list[
            MLURLIdentityKey
        ] = []

        for sample in samples:
            if len(accepted) >= remaining_target:
                break

            identity_key: MLURLIdentityKey = (
                sample.canonicalization_version,
                sample.value_hash,
            )

            if identity_key in threat_identity_keys:
                threat_rejected += 1
                continue

            if (
                group_counts[
                    sample.group_key
                ]
                >= self._max_per_domain
            ):
                domain_quota_rejected += 1
                continue

            accepted.append(sample)

            accepted_identity_keys.append(
                identity_key
            )

            # Réservation locale du quota.
            # Le CLI est mono-processus.
            group_counts[
                sample.group_key
            ] += 1

        if not accepted:
            return (
                0,
                threat_rejected,
                domain_quota_rejected,
            )

        result = self._store.persist_benign_batch(
            dataset_id=dataset_id,
            samples=accepted,
        )

        if (
            result.inserted_members
            != len(accepted)
        ):
            # Un conflit concurrent/idempotent est possible.
            # On relit l'état depuis les méthodes du contrat
            # MLDatasetStore au lieu d'utiliser une méthode
            # inexistante ou non typée.
            refreshed_group_counts = Counter(
                self._store.get_member_group_counts(
                    dataset_id=dataset_id,
                    label_code=self.LABEL_CODE,
                )
            )

            group_counts.clear()
            group_counts.update(
                refreshed_group_counts
            )

            refreshed_identity_keys = (
                self._store.get_member_identity_keys(
                    dataset_id=dataset_id,
                    label_code=self.LABEL_CODE,
                )
            )

            existing_identity_keys.clear()
            existing_identity_keys.update(
                refreshed_identity_keys
            )

        else:
            existing_identity_keys.update(
                accepted_identity_keys
            )

        return (
            result.inserted_members,
            threat_rejected,
            domain_quota_rejected,
        )

    @staticmethod
    def _normalize_registered_domain(
        value: str,
    ) -> str:
        if not isinstance(value, str):
            raise BenignCandidateValidationError(
                "registered domain must "
                "be a string"
            )

        candidate = (
            value
            .strip()
            .lower()
            .rstrip(".")
        )

        if not candidate:
            raise BenignCandidateValidationError(
                "registered domain "
                "must not be empty"
            )

        try:
            ip_address(candidate)

        except ValueError:
            pass

        else:
            raise BenignCandidateValidationError(
                "registered domain "
                "must not be an IP address"
            )

        try:
            normalized = (
                candidate
                .encode("idna")
                .decode("ascii")
                .lower()
            )

        except UnicodeError:
            raise BenignCandidateValidationError(
                "registered domain "
                "is invalid"
            ) from None

        labels = normalized.split(".")

        if (
            len(labels) < 2
            or any(
                not label
                or len(label) > 63
                for label in labels
            )
        ):
            raise BenignCandidateValidationError(
                "registered domain "
                "is invalid"
            )

        return normalized

    @staticmethod
    def _hostname_belongs_to_domain(
        *,
        hostname: str,
        registered_domain: str,
    ) -> bool:
        return (
            hostname == registered_domain
            or hostname.endswith(
                f".{registered_domain}"
            )
        )

    @classmethod
    def _validate_batch_size(
        cls,
        value: int,
    ) -> None:
        cls._validate_positive_integer(
            name="batch_size",
            value=value,
        )

        if value > cls.MAX_BATCH_SIZE:
            raise ValueError(
                "batch_size must not exceed "
                f"{cls.MAX_BATCH_SIZE}"
            )

    @staticmethod
    def _validate_positive_integer(
        *,
        name: str,
        value: int,
    ) -> None:
        if (
            isinstance(value, bool)
            or not isinstance(value, int)
        ):
            raise TypeError(
                f"{name} must be an integer"
            )

        if value < 1:
            raise ValueError(
                f"{name} must be greater than zero"
            )