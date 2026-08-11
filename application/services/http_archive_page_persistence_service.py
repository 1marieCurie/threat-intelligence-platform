from __future__ import annotations

from collections.abc import Iterable

from application.models.http_archive_page import (
    HTTPArchivePersistenceResult,
    PreparedHTTPArchivePage,
)
from application.models.ml_dataset import (
    BenignURLCandidate,
)
from application.ports.outbound.http_archive_page import (
    HTTPArchivePageStore,
)
from application.services.canonical_url_normalizer import (
    CanonicalURLNormalizationError,
    CanonicalURLNormalizer,
)


class HTTPArchiveCandidateValidationError(
    ValueError
):
    pass


class HTTPArchivePagePersistenceService:
    """
    Normalise puis persiste les candidats HTTP Archive.

    Cette étape :
    - ne crée aucun label ML ;
    - n'effectue aucune projection ;
    - n'extrait aucune feature ;
    - conserve la représentation canonique complète.
    """

    DEFAULT_BATCH_SIZE = 1_000
    MAX_BATCH_SIZE = 2_000

    def __init__(
        self,
        *,
        store: HTTPArchivePageStore,
        normalizer: CanonicalURLNormalizer,
        expected_source_snapshot: str,
        batch_size: int = DEFAULT_BATCH_SIZE,
    ) -> None:
        source_snapshot = (
            expected_source_snapshot.strip()
        )

        if not source_snapshot:
            raise ValueError(
                "expected_source_snapshot "
                "must not be empty"
            )

        if (
            isinstance(batch_size, bool)
            or not isinstance(batch_size, int)
            or batch_size < 1
            or batch_size > self.MAX_BATCH_SIZE
        ):
            raise ValueError(
                "batch_size must be between "
                f"1 and {self.MAX_BATCH_SIZE}"
            )

        self._store = store
        self._normalizer = normalizer

        self._expected_source_snapshot = (
            source_snapshot
        )

        self._batch_size = batch_size

    def run(
        self,
        candidates: Iterable[
            BenignURLCandidate
        ],
    ) -> HTTPArchivePersistenceResult:
        candidates_read = 0
        normalized = 0

        normalization_rejected = 0
        source_rejected = 0

        submitted = 0
        inserted = 0

        pending: list[
            PreparedHTTPArchivePage
        ] = []

        for candidate in candidates:
            candidates_read += 1

            try:
                prepared = self._prepare(
                    candidate
                )

            except CanonicalURLNormalizationError:
                normalization_rejected += 1
                continue

            except HTTPArchiveCandidateValidationError:
                source_rejected += 1
                continue

            normalized += 1

            pending.append(
                prepared
            )

            if (
                len(pending)
                >= self._batch_size
            ):
                submitted += len(
                    pending
                )

                inserted += (
                    self._store.persist_batch(
                        pending
                    )
                )

                pending.clear()

        if pending:
            submitted += len(
                pending
            )

            inserted += (
                self._store.persist_batch(
                    pending
                )
            )

        return HTTPArchivePersistenceResult(
            candidates_read=(
                candidates_read
            ),
            normalized=normalized,
            normalization_rejected=(
                normalization_rejected
            ),
            source_rejected=(
                source_rejected
            ),
            submitted=submitted,
            inserted=inserted,
            already_existing=(
                submitted
                - inserted
            ),
        )

    def _prepare(
        self,
        candidate: BenignURLCandidate,
    ) -> PreparedHTTPArchivePage:
        source_snapshot = (
            candidate.source_snapshot.strip()
        )

        if (
            source_snapshot
            != self._expected_source_snapshot
        ):
            raise HTTPArchiveCandidateValidationError(
                "candidate source snapshot mismatch"
            )

        if candidate.source_rank <= 0:
            raise HTTPArchiveCandidateValidationError(
                "candidate source rank is invalid"
            )

        registered_domain = (
            candidate.registered_domain
            .strip()
            .lower()
            .rstrip(".")
        )

        if not registered_domain:
            raise HTTPArchiveCandidateValidationError(
                "registered domain is invalid"
            )

        identity = (
            self._normalizer.normalize(
                candidate.url
            )
        )

        hostname = (
            identity.hostname
        )

        if not (
            hostname
            == registered_domain
            or hostname.endswith(
                f".{registered_domain}"
            )
        ):
            raise HTTPArchiveCandidateValidationError(
                "hostname does not belong "
                "to registered domain"
            )

        return PreparedHTTPArchivePage(
            canonical_value=(
                identity.canonical_value
            ),
            value_hash=(
                identity.value_hash
            ),
            hostname=(
                identity.hostname
            ),
            registered_domain=(
                registered_domain
            ),
            canonicalization_version=(
                identity.canonicalization_version
            ),
            source_rank=(
                candidate.source_rank
            ),
            source_snapshot=(
                source_snapshot
            ),
            observed_at=(
                candidate.observed_at
            ),
        )