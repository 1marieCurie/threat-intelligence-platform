from __future__ import annotations

import re
from collections.abc import Iterable, Mapping

from application.models.epss_snapshot import (
    EPSSSnapshot,
)
from application.ports.outbound.unit_of_work import (
    UnitOfWork,
)


_CVE_PATTERN = re.compile(
    r"^CVE-\d{4}-\d{4,}$"
)


class EPSSLookupService:
    """
    Lit les derniers snapshots EPSS persistés localement.

    Ce service est indépendant du modèle historique Threat
    et ne contacte jamais directement le fournisseur FIRST.

    Flux :

    identifiants CVE
        -> normalisation et déduplication
        -> lecture PostgreSQL groupée
        -> fermeture de la transaction
        -> validation et remise en ordre du résultat
    """

    DEFAULT_MAX_CVE_IDS = 50_000

    def __init__(
        self,
        *,
        unit_of_work: UnitOfWork,
        max_cve_ids: int = DEFAULT_MAX_CVE_IDS,
    ) -> None:
        if unit_of_work is None:
            raise ValueError(
                "unit_of_work must not be None"
            )

        self._validate_positive_integer(
            value=max_cve_ids,
            field_name="max_cve_ids",
        )

        self._unit_of_work = unit_of_work
        self._max_cve_ids = max_cve_ids

    def find_many_by_cve_ids(
        self,
        cve_ids: Iterable[str | None],
    ) -> dict[str, EPSSSnapshot]:
        """
        Retourne les snapshots EPSS indexés par CVE.

        Les identifiants invalides sont ignorés. Les CVE valides
        sont normalisés, dédupliqués et retournés dans l'ordre
        de leur première apparition.

        Une seule lecture groupée du repository est effectuée.
        """
        normalized_cve_ids = (
            self._normalize_cve_ids(
                cve_ids
            )
        )

        if not normalized_cve_ids:
            return {}

        if (
            len(normalized_cve_ids)
            > self._max_cve_ids
        ):
            raise ValueError(
                "cve_ids exceeds the configured "
                f"limit of {self._max_cve_ids}"
            )

        # La transaction reste strictement limitée
        # à la lecture groupée du repository.
        with self._unit_of_work as unit_of_work:
            snapshots = (
                unit_of_work.epss_scores
                .find_many_by_cve_ids(
                    normalized_cve_ids
                )
            )

        # La validation métier du résultat est réalisée
        # après la fermeture de la transaction.
        return self._validate_and_order_snapshots(
            requested_cve_ids=normalized_cve_ids,
            snapshots=snapshots,
        )

    @staticmethod
    def _normalize_cve_ids(
        cve_ids: Iterable[str | None],
    ) -> list[str]:
        if isinstance(
            cve_ids,
            (str, bytes),
        ):
            raise TypeError(
                "cve_ids must be an iterable "
                "of identifiers"
            )

        try:
            iterator = iter(
                cve_ids
            )

        except TypeError as error:
            raise TypeError(
                "cve_ids must be iterable"
            ) from error

        normalized_cve_ids: list[str] = []
        seen: set[str] = set()

        for cve_id in iterator:
            if cve_id is None:
                continue

            if not isinstance(
                cve_id,
                str,
            ):
                continue

            normalized_cve_id = (
                cve_id
                .strip()
                .upper()
            )

            if not _CVE_PATTERN.fullmatch(
                normalized_cve_id
            ):
                continue

            if normalized_cve_id in seen:
                continue

            seen.add(
                normalized_cve_id
            )

            normalized_cve_ids.append(
                normalized_cve_id
            )

        return normalized_cve_ids

    @staticmethod
    def _validate_and_order_snapshots(
        *,
        requested_cve_ids: list[str],
        snapshots: Mapping[
            str,
            EPSSSnapshot,
        ],
    ) -> dict[str, EPSSSnapshot]:
        if not isinstance(
            snapshots,
            Mapping,
        ):
            raise TypeError(
                "epss repository result "
                "must be a mapping"
            )

        unexpected_cve_ids = (
            set(snapshots)
            - set(requested_cve_ids)
        )

        if unexpected_cve_ids:
            raise RuntimeError(
                "epss repository returned "
                "unexpected CVE identifiers"
            )

        ordered_snapshots: dict[
            str,
            EPSSSnapshot,
        ] = {}

        for cve_id in requested_cve_ids:
            snapshot = snapshots.get(
                cve_id
            )

            if snapshot is None:
                continue

            if not isinstance(
                snapshot,
                EPSSSnapshot,
            ):
                raise TypeError(
                    "epss repository values must "
                    "be EPSSSnapshot instances"
                )

            ordered_snapshots[
                cve_id
            ] = snapshot

        return ordered_snapshots

    @staticmethod
    def _validate_positive_integer(
        *,
        value: int,
        field_name: str,
    ) -> None:
        if (
            isinstance(value, bool)
            or not isinstance(value, int)
        ):
            raise TypeError(
                f"{field_name} must be an integer"
            )

        if value < 1:
            raise ValueError(
                f"{field_name} must be "
                "greater than zero"
            )