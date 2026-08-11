from __future__ import annotations

import csv
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path

from application.models.ml_dataset import (
    BenignURLCandidate,
)


class BenignCandidateCSVError(RuntimeError):
    """
    Erreur de lecture du fichier candidat.

    Les messages ne contiennent volontairement ni URL,
    ni contenu de ligne afin d'éviter toute fuite.
    """


class BenignCandidateCSVSource:
    """
    Lit en streaming un CSV de candidats benign.

    Le contrat CSV est indépendant du fournisseur :
    - url
    - registered_domain
    - source_rank
    - source_snapshot
    - observed_at
    """

    REQUIRED_FIELDS = frozenset(
        {
            "url",
            "registered_domain",
            "source_rank",
            "source_snapshot",
            "observed_at",
        }
    )

    def __init__(
        self,
        *,
        path: Path,
    ) -> None:
        if not isinstance(path, Path):
            raise TypeError(
                "path must be a Path"
            )

        self._path = path

    def iter_candidates(
        self,
    ) -> Iterator[BenignURLCandidate]:
        try:
            handle = self._path.open(
                "r",
                encoding="utf-8",
                newline="",
            )

        except OSError:
            raise BenignCandidateCSVError(
                "Unable to open benign candidate file"
            ) from None

        with handle:
            reader = csv.DictReader(
                handle
            )

            fields = set(
                reader.fieldnames or ()
            )

            if not (
                self.REQUIRED_FIELDS
                <= fields
            ):
                raise BenignCandidateCSVError(
                    "Benign candidate CSV schema is invalid"
                )

            for row_number, row in enumerate(
                reader,
                start=2,
            ):
                try:
                    url = row["url"].strip()

                    registered_domain = (
                        row["registered_domain"]
                        .strip()
                        .lower()
                    )

                    source_rank = int(
                        row["source_rank"]
                    )

                    source_snapshot = (
                        row["source_snapshot"]
                        .strip()
                    )

                    raw_observed_at = (
                        row["observed_at"]
                        .strip()
                    )

                    observed_at = (
                        datetime.fromisoformat(
                            raw_observed_at.replace(
                                "Z",
                                "+00:00",
                            )
                        )
                    )

                    if (
                        observed_at.tzinfo is None
                        or observed_at.utcoffset()
                        is None
                    ):
                        raise ValueError

                    observed_at = (
                        observed_at.astimezone(
                            timezone.utc
                        )
                    )

                    if (
                        not url
                        or not registered_domain
                        or not source_snapshot
                        or source_rank <= 0
                    ):
                        raise ValueError

                    yield BenignURLCandidate(
                        url=url,
                        registered_domain=(
                            registered_domain
                        ),
                        source_rank=source_rank,
                        source_snapshot=(
                            source_snapshot
                        ),
                        observed_at=observed_at,
                    )

                except (
                    KeyError,
                    TypeError,
                    ValueError,
                ):
                    # Ne jamais inclure row ou url
                    # dans le message d'erreur.
                    raise BenignCandidateCSVError(
                        "Invalid benign candidate "
                        f"at row {row_number}"
                    ) from None