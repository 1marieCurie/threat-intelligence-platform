from __future__ import annotations

from sqlalchemy import (
    literal,
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
from infrastructure.persistence.models.normalized import (
    GitHubAdvisoryVulnerabilityModel,
)


class SqlAlchemyGitHubAdvisoryCanonicalSource(
    GitHubAdvisoryCanonicalSource
):
    """
    Reader PostgreSQL des advisories GitHub
    destinés à la corrélation canonique.

    La requête :

    - utilise une pagination keyset ;
    - filtre les advisories retirés en SQL ;
    - sélectionne uniquement six colonnes ;
    - n'accède jamais au schéma raw.
    """

    DEFAULT_BATCH_SIZE = 500
    MAX_BATCH_SIZE = 1_000

    def __init__(
        self,
        *,
        session: Session,
    ) -> None:
        if session is None:
            raise ValueError(
                "session must not be None"
            )

        self._session = session

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

        statement = (
            select(
                GitHubAdvisoryVulnerabilityModel.id,
                GitHubAdvisoryVulnerabilityModel
                .ghsa_id,
                GitHubAdvisoryVulnerabilityModel
                .cve_id,
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

        if normalized_cursor is not None:
            statement = statement.where(
                tuple_(
                    GitHubAdvisoryVulnerabilityModel
                    .ghsa_id,
                    GitHubAdvisoryVulnerabilityModel
                    .id,
                )
                > tuple_(
                    literal(
                        normalized_cursor.ghsa_id
                    ),
                    literal(
                        normalized_cursor.normalized_record_id
                    ),
                )
            )

        statement = (
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
                normalized_limit
            )
        )

        rows = (
            self._session
            .execute(statement)
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
                published_at=published_at,
                updated_at=updated_at,
                withdrawn_at=None,
                normalized_at=normalized_at,
            )
            for (
                normalized_record_id,
                ghsa_id,
                cve_id,
                published_at,
                updated_at,
                normalized_at,
            )
            in rows
        )

    @classmethod
    def _validate_limit(
        cls,
        value: int,
    ) -> int:
        if (
            isinstance(value, bool)
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