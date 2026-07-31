from __future__ import annotations

import re
from collections.abc import (
    Iterable,
    Mapping,
)
from dataclasses import dataclass
from datetime import date, datetime

from application.models.epss_snapshot import (
    EPSSSnapshot,
)
from application.ports.outbound.epss_provider import (
    EPSSProvider,
)
from application.ports.outbound.unit_of_work import (
    UnitOfWork,
)


@dataclass(
    frozen=True,
    slots=True,
)
class EPSSSynchronizationResult:
    """
    Résultat d'une synchronisation EPSS.

    submitted_scores correspond aux snapshots transmis au
    repository. Le repository peut ignorer une mise à jour
    lorsque sa date est antérieure à la valeur persistée.
    """

    requested_cves: int
    fetched_scores: int
    submitted_scores: int

    missing_cves: tuple[str, ...] = ()

    requested_score_date: date | None = None


class EPSSSynchronizationService:
    """
    Synchronise les scores FIRST EPSS vers PostgreSQL.

    L'appel HTTP est exécuté avant l'ouverture de la
    transaction PostgreSQL. La transaction contient uniquement
    l'upsert et le commit.
    """

    CVE_ID_PATTERN = re.compile(
        r"^CVE-[0-9]{4}-[0-9]{4,}$",
        re.IGNORECASE,
    )

    DEFAULT_MAX_CVE_IDS = 50_000

    def __init__(
        self,
        *,
        provider: EPSSProvider,
        unit_of_work: UnitOfWork,
        max_cve_ids: int = DEFAULT_MAX_CVE_IDS,
    ) -> None:
        if provider is None:
            raise ValueError(
                "provider is required"
            )

        if unit_of_work is None:
            raise ValueError(
                "unit_of_work is required"
            )

        self._validate_positive_integer(
            max_cve_ids,
            field_name="max_cve_ids",
        )

        self._provider = provider
        self._unit_of_work = unit_of_work
        self._max_cve_ids = max_cve_ids

    def synchronize(
        self,
        cve_ids: Iterable[str],
        *,
        score_date: date | None = None,
    ) -> EPSSSynchronizationResult:
        """
        Récupère et persiste les scores EPSS des CVE demandés.

        Les CVE sont validés, normalisés et dédupliqués avant
        tout appel au fournisseur.
        """
        self._validate_score_date(
            score_date
        )

        normalized_cve_ids = (
            self._normalize_cve_ids(
                cve_ids
            )
        )

        if not normalized_cve_ids:
            return EPSSSynchronizationResult(
                requested_cves=0,
                fetched_scores=0,
                submitted_scores=0,
                requested_score_date=score_date,
            )

        # L'appel réseau reste volontairement en dehors
        # de toute transaction PostgreSQL.
        provider_snapshots = (
            self._provider.fetch_by_cve_ids(
                normalized_cve_ids,
                score_date=score_date,
            )
        )

        snapshots = self._validate_provider_result(
            values=provider_snapshots,
            requested_cve_ids=normalized_cve_ids,
            requested_score_date=score_date,
        )

        missing_cves = tuple(
            cve_id
            for cve_id in normalized_cve_ids
            if cve_id not in snapshots
        )

        if not snapshots:
            return EPSSSynchronizationResult(
                requested_cves=len(
                    normalized_cve_ids
                ),
                fetched_scores=0,
                submitted_scores=0,
                missing_cves=missing_cves,
                requested_score_date=score_date,
            )

        with self._unit_of_work as uow:
            submitted_scores = (
                uow.epss_scores.upsert_many(
                    snapshots
                )
            )

            uow.commit()

        return EPSSSynchronizationResult(
            requested_cves=len(
                normalized_cve_ids
            ),
            fetched_scores=len(
                snapshots
            ),
            submitted_scores=(
                submitted_scores
            ),
            missing_cves=missing_cves,
            requested_score_date=score_date,
        )

    def _normalize_cve_ids(
        self,
        values: Iterable[str],
    ) -> list[str]:
        if isinstance(
            values,
            (str, bytes),
        ):
            raise TypeError(
                "cve_ids must be an iterable "
                "of strings"
            )

        try:
            iterator = iter(values)
        except TypeError as error:
            raise TypeError(
                "cve_ids must be an iterable "
                "of strings"
            ) from error

        normalized_values: list[str] = []
        seen: set[str] = set()

        for value in iterator:
            normalized_value = (
                self._normalize_cve_id(
                    value
                )
            )

            if normalized_value in seen:
                continue

            normalized_values.append(
                normalized_value
            )

            seen.add(
                normalized_value
            )

            if (
                len(normalized_values)
                > self._max_cve_ids
            ):
                raise RuntimeError(
                    "EPSS CVE identifier limit "
                    "was exceeded"
                )

        return normalized_values

    @classmethod
    def _normalize_cve_id(
        cls,
        value: str,
    ) -> str:
        if not isinstance(
            value,
            str,
        ):
            raise TypeError(
                "Every CVE identifier must "
                "be a string"
            )

        normalized_value = (
            value.strip().upper()
        )

        if (
            len(normalized_value) > 32
            or cls.CVE_ID_PATTERN.fullmatch(
                normalized_value
            )
            is None
        ):
            raise ValueError(
                "Every value must be a valid "
                "CVE identifier"
            )

        return normalized_value

    @classmethod
    def _validate_provider_result(
        cls,
        *,
        values: Mapping[
            str,
            EPSSSnapshot,
        ],
        requested_cve_ids: list[str],
        requested_score_date: date | None,
    ) -> dict[str, EPSSSnapshot]:
        if not isinstance(
            values,
            Mapping,
        ):
            raise TypeError(
                "EPSS provider result must "
                "be a mapping"
            )

        requested_cve_set = set(
            requested_cve_ids
        )

        validated_values: dict[
            str,
            EPSSSnapshot,
        ] = {}

        for cve_id, snapshot in values.items():
            normalized_cve_id = (
                cls._normalize_cve_id(
                    cve_id
                )
            )

            if cve_id != normalized_cve_id:
                raise ValueError(
                    "EPSS provider returned a "
                    "non-normalized CVE identifier"
                )

            if (
                normalized_cve_id
                not in requested_cve_set
            ):
                raise ValueError(
                    "EPSS provider returned an "
                    "unexpected CVE identifier"
                )

            if not isinstance(
                snapshot,
                EPSSSnapshot,
            ):
                raise TypeError(
                    "EPSS provider values must "
                    "be EPSSSnapshot instances"
                )

            if (
                requested_score_date is not None
                and snapshot.score_date
                != requested_score_date
            ):
                raise ValueError(
                    "EPSS provider returned a score "
                    "date that does not match the "
                    "requested date"
                )

            validated_values[
                normalized_cve_id
            ] = snapshot

        return {
            cve_id: validated_values[cve_id]
            for cve_id in requested_cve_ids
            if cve_id in validated_values
        }

    @staticmethod
    def _validate_score_date(
        value: date | None,
    ) -> None:
        if value is None:
            return

        if (
            not isinstance(value, date)
            or isinstance(value, datetime)
        ):
            raise TypeError(
                "score_date must be a date "
                "or None"
            )

    @staticmethod
    def _validate_positive_integer(
        value: int,
        *,
        field_name: str,
    ) -> None:
        if (
            isinstance(value, bool)
            or not isinstance(value, int)
        ):
            raise TypeError(
                f"{field_name} must be an integer"
            )

        if value <= 0:
            raise ValueError(
                f"{field_name} must be greater "
                "than zero"
            )