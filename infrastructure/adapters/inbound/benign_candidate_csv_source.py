from __future__ import annotations

import csv
from collections.abc import Iterator
from pathlib import Path

from application.models.ml_dataset import (
    BenignURLCandidate,
)


class BenignCandidateCSVError(RuntimeError):
    """
    Erreur de lecture du fichier candidat.

    Le message ne contient volontairement ni URL,
    ni contenu de ligne afin d'éviter toute fuite.
    """


class BenignCandidateCSVSource:
    """
    Lit en streaming le CSV temporaire Tranco + CrUX.

    Le fichier actuellement généré utilise encore les colonnes
    historiques `crux_present` et `crawl_id`.

    Elles sont confinées ici :
        crawl_id -> source_snapshot

    La couche application ne connaît donc pas Common Crawl.
    """

    REQUIRED_FIELDS = frozenset(
        {
            "url",
            "registered_domain",
            "tranco_rank",
            "crux_present",
            "crawl_id",
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
                    crux_present = (
                        row["crux_present"]
                        .strip()
                        .lower()
                    )

                    if crux_present != "true":
                        continue

                    url = (
                        row["url"]
                        .strip()
                    )

                    registered_domain = (
                        row["registered_domain"]
                        .strip()
                        .lower()
                    )

                    tranco_rank = int(
                        row["tranco_rank"]
                    )

                    source_snapshot = (
                        row["crawl_id"]
                        .strip()
                    )

                    if (
                        not url
                        or not registered_domain
                        or not source_snapshot
                        or tranco_rank <= 0
                    ):
                        raise ValueError

                    yield BenignURLCandidate(
                        url=url,
                        registered_domain=registered_domain,
                        tranco_rank=tranco_rank,
                        source_snapshot=source_snapshot,
                    )

                except (
                    KeyError,
                    TypeError,
                    ValueError,
                ):
                    # Important :
                    # ne jamais inclure row ou url
                    # dans le message d'erreur.
                    raise BenignCandidateCSVError(
                        "Invalid benign candidate "
                        f"at row {row_number}"
                    ) from None