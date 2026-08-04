from __future__ import annotations

from abc import ABC, abstractmethod

from application.models.github_advisory_canonical_source_record import (
    GitHubAdvisoryCanonicalCursor,
    GitHubAdvisoryCanonicalSourceRecord,
)


class GitHubAdvisoryCanonicalSource(ABC):
    """
    Port paginé de lecture des GitHub Security
    Advisories normalisés et non retirés.
    """

    @abstractmethod
    def read_batch(
        self,
        *,
        after_cursor: (
            GitHubAdvisoryCanonicalCursor
            | None
        ) = None,
        limit: int = 500,
    ) -> tuple[
        GitHubAdvisoryCanonicalSourceRecord,
        ...,
    ]:
        """
        Retourne un lot ordonné par :

            ghsa_id ASC,
            normalized_record_id ASC

        Les advisories retirés sont exclus.
        after_cursor est exclusif.
        """