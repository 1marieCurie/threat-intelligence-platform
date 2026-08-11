from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol

from application.models.http_archive_page import (
    PreparedHTTPArchivePage,
)


class HTTPArchivePageStore(Protocol):
    def persist_batch(
        self,
        records: Sequence[
            PreparedHTTPArchivePage
        ],
    ) -> int:
        """
        Persiste un batch de manière idempotente.

        Retourne le nombre de nouvelles lignes insérées.
        """
        ...