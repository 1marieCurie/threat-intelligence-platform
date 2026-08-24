from __future__ import annotations

from sqlalchemy import (
    String,
    and_,
    cast,
    func,
    literal,
    or_,
    select,
    tuple_,
)
from sqlalchemy.orm import Session

from application.models.github_advisory_canonical_source_record import (
    GitHubAdvisoryCanonicalCursor,
    GitHubAdvisoryCanonicalSourceRecord,
)
from application.ports.outbound.github_advisory_canonical_source import (
    GitHubAdvisoryCanonicalSource,
)
from infrastructure.persistence.models.canonical import (
    CanonicalVulnerabilityEvidenceModel,
)
from infrastructure.persistence.models.normalized import (
    GitHubAdvisoryVulnerabilityModel,
)


GITHUB_ADVISORY_EVIDENCE_SOURCE = (
    "github_advisory"
)


class SqlAlchemyGitHubAdvisoryCanonicalSource(
    GitHubAdvisoryCanonicalSource
):
    """
    Reader PostgreSQL des advisories GitHub destinés
    à la couche canonique.

    Mode complet, par défaut :
        conserve le comportement historique et lit toutes
        les lignes normalisées non retirées.

    Mode incremental_only :
        - conserve uniquement la version normalisée la plus
          récente de chaque GHSA ;
        - ignore les GHSA dont l'evidence canonique référence
          déjà exactement cette version normalisée ;
        - retourne donc uniquement les advisories nouveaux
          ou réellement actualisés.

    Aucun état scheduler supplémentaire n'est nécessaire :
    canonical_vulnerability_evidence sert naturellement
    de preuve du dernier record canonicalisé.
    """

    DEFAULT_BATCH_SIZE = 500
    MAX_BATCH_SIZE = 1_000

    def __init__(
        self,
        *,
        session: Session,
        incremental_only: bool = False,
    ) -> None:
        if session is None:
            raise ValueError(
                "session must not be None"
            )

        if not isinstance(
            incremental_only,
            bool,
        ):
            raise TypeError(
                "incremental_only must be a boolean"
            )

        self._session = session
        self._incremental_only = (
            incremental_only
        )

    def read_batch(
        self,
        *,
        after_cursor: (
            GitHubAdvisoryCanonicalCursor
            | None
        ) = None,
        limit: int = DEFAULT_BATCH_SIZE,
    ) -> tuple[
        GitHubAdvisoryCanonicalSourceRecord,
        ...,
    ]:
        normalized_limit = (
            self._validate_limit(
                limit
            )
        )

        normalized_cursor = (
            self._validate_cursor(
                after_cursor
            )
        )

        if self._incremental_only:
            statement = (
                self._build_incremental_statement(
                    after_cursor=(
                        normalized_cursor
                    ),
                    limit=(
                        normalized_limit
                    ),
                )
            )

        else:
            statement = (
                self._build_complete_statement(
                    after_cursor=(
                        normalized_cursor
                    ),
                    limit=(
                        normalized_limit
                    ),
                )
            )

        rows = (
            self._session
            .execute(
                statement
            )
            .tuples()
            .all()
        )

        return tuple(
            GitHubAdvisoryCanonicalSourceRecord(
                normalized_record_id=(
                    normalized_record_id
                ),
                ghsa_id=ghsa_id,
                source_ghsa_id=ghsa_id,
                cve_id=cve_id,
                cwe_ids=tuple(
                    cwe_ids or ()
                ),
                published_at=published_at,
                updated_at=updated_at,
                withdrawn_at=None,
                normalized_at=normalized_at,
            )
            for (
                normalized_record_id,
                ghsa_id,
                cve_id,
                cwe_ids,
                published_at,
                updated_at,
                normalized_at,
            )
            in rows
        )

    @staticmethod
    def _build_complete_statement(
        *,
        after_cursor: (
            GitHubAdvisoryCanonicalCursor
            | None
        ),
        limit: int,
    ):
        statement = (
            select(
                GitHubAdvisoryVulnerabilityModel.id,
                GitHubAdvisoryVulnerabilityModel
                .ghsa_id,
                GitHubAdvisoryVulnerabilityModel
                .cve_id,
                GitHubAdvisoryVulnerabilityModel
                .cwe_ids,
                GitHubAdvisoryVulnerabilityModel
                .published_at,
                GitHubAdvisoryVulnerabilityModel
                .updated_at,
                GitHubAdvisoryVulnerabilityModel
                .normalized_at,
            )
            .where(
                GitHubAdvisoryVulnerabilityModel
                .withdrawn_at
                .is_(None)
            )
        )

        if after_cursor is not None:
            statement = (
                statement.where(
                    tuple_(
                        GitHubAdvisoryVulnerabilityModel
                        .ghsa_id,
                        GitHubAdvisoryVulnerabilityModel
                        .id,
                    )
                    > tuple_(
                        literal(
                            after_cursor.ghsa_id
                        ),
                        literal(
                            after_cursor
                            .normalized_record_id
                        ),
                    )
                )
            )

        return (
            statement
            .order_by(
                GitHubAdvisoryVulnerabilityModel
                .ghsa_id
                .asc(),
                GitHubAdvisoryVulnerabilityModel
                .id
                .asc(),
            )
            .limit(
                limit
            )
        )

    @staticmethod
    def _build_incremental_statement(
        *,
        after_cursor: (
            GitHubAdvisoryCanonicalCursor
            | None
        ),
        limit: int,
    ):
        """
        Construit un ensemble contenant uniquement
        la version la plus récente de chaque GHSA.

        updated_at est prioritaire car il reflète
        la version fournisseur.

        normalized_at puis id stabilisent le choix
        lorsque updated_at est absent ou identique.
        """

        ranked_records = (
            select(
                GitHubAdvisoryVulnerabilityModel
                .id
                .label(
                    "id"
                ),
                GitHubAdvisoryVulnerabilityModel
                .ghsa_id
                .label(
                    "ghsa_id"
                ),
                GitHubAdvisoryVulnerabilityModel
                .cve_id
                .label(
                    "cve_id"
                ),
                GitHubAdvisoryVulnerabilityModel
                .cwe_ids
                .label(
                    "cwe_ids"
                ),
                GitHubAdvisoryVulnerabilityModel
                .published_at
                .label(
                    "published_at"
                ),
                GitHubAdvisoryVulnerabilityModel
                .updated_at
                .label(
                    "updated_at"
                ),
                GitHubAdvisoryVulnerabilityModel
                .normalized_at
                .label(
                    "normalized_at"
                ),
                func.row_number()
                .over(
                    partition_by=(
                        GitHubAdvisoryVulnerabilityModel
                        .ghsa_id
                    ),
                    order_by=(
                        GitHubAdvisoryVulnerabilityModel
                        .updated_at
                        .desc()
                        .nullslast(),
                        GitHubAdvisoryVulnerabilityModel
                        .normalized_at
                        .desc(),
                        GitHubAdvisoryVulnerabilityModel
                        .id
                        .desc(),
                    ),
                )
                .label(
                    "version_rank"
                ),
            )
            .where(
                GitHubAdvisoryVulnerabilityModel
                .withdrawn_at
                .is_(None)
            )
            .subquery(
                "latest_github_advisory"
            )
        )

        evidence = (
            CanonicalVulnerabilityEvidenceModel
        )

        statement = (
            select(
                ranked_records.c.id,
                ranked_records.c.ghsa_id,
                ranked_records.c.cve_id,
                ranked_records.c.cwe_ids,
                ranked_records.c.published_at,
                ranked_records.c.updated_at,
                ranked_records.c.normalized_at,
            )
            .select_from(
                ranked_records
            )
            .outerjoin(
                evidence,
                and_(
                    evidence.source
                    == (
                        GITHUB_ADVISORY_EVIDENCE_SOURCE
                    ),
                    evidence.source_record_key
                    == func.upper(
                        ranked_records.c.ghsa_id
                    ),
                ),
            )
            .where(
                ranked_records.c.version_rank
                == 1
            )
            .where(
                or_(
                    evidence.id.is_(None),
                    evidence.normalized_record_id
                    != cast(
                        ranked_records.c.id,
                        String,
                    ),
                )
            )
        )

        if after_cursor is not None:
            statement = (
                statement.where(
                    tuple_(
                        ranked_records.c.ghsa_id,
                        ranked_records.c.id,
                    )
                    > tuple_(
                        literal(
                            after_cursor.ghsa_id
                        ),
                        literal(
                            after_cursor
                            .normalized_record_id
                        ),
                    )
                )
            )

        return (
            statement
            .order_by(
                ranked_records.c.ghsa_id
                .asc(),
                ranked_records.c.id
                .asc(),
            )
            .limit(
                limit
            )
        )

    @classmethod
    def _validate_limit(
        cls,
        value: int,
    ) -> int:
        if (
            isinstance(
                value,
                bool,
            )
            or not isinstance(
                value,
                int,
            )
        ):
            raise TypeError(
                "limit must be an integer"
            )

        if not (
            1
            <= value
            <= cls.MAX_BATCH_SIZE
        ):
            raise ValueError(
                "limit must be between 1 "
                f"and {cls.MAX_BATCH_SIZE}"
            )

        return value

    @staticmethod
    def _validate_cursor(
        value: (
            GitHubAdvisoryCanonicalCursor
            | None
        ),
    ) -> (
        GitHubAdvisoryCanonicalCursor
        | None
    ):
        if value is None:
            return None

        if not isinstance(
            value,
            GitHubAdvisoryCanonicalCursor,
        ):
            raise TypeError(
                "after_cursor must be a "
                "GitHubAdvisoryCanonicalCursor "
                "or None"
            )

        return value