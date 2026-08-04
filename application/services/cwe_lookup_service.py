from __future__ import annotations

import re
from collections.abc import Iterable

from application.ports.outbound.unit_of_work import (
    UnitOfWork,
)
from domain.cwe_weakness import CWEWeakness


_CWE_ID_PATTERN = re.compile(
    r"^(?:CWE-)?(\d+)$",
    re.IGNORECASE,
)


class CWELookupService:
    """
    Lit les faiblesses CWE persistées localement.

    Ce service est indépendant du modèle historique Threat
    et ne contacte jamais directement MITRE.

    Flux :

    identifiants CWE
        -> normalisation et déduplication
        -> lecture PostgreSQL groupée
        -> fermeture de la transaction
        -> validation et remise en ordre du résultat
    """

    DEFAULT_MAX_CWE_IDS = 10_000
    MAX_CWE_ID_LENGTH = 32

    def __init__(
        self,
        *,
        unit_of_work: UnitOfWork,
        max_cwe_ids: int = DEFAULT_MAX_CWE_IDS,
    ) -> None:
        if unit_of_work is None:
            raise ValueError(
                "unit_of_work must not be None"
            )

        self._validate_positive_integer(
            value=max_cwe_ids,
            field_name="max_cwe_ids",
        )

        self._unit_of_work = unit_of_work
        self._max_cwe_ids = max_cwe_ids

    def find_many_by_cwe_ids(
        self,
        cwe_ids: Iterable[str | None],
    ) -> dict[str, CWEWeakness]:
        """
        Retourne les faiblesses indexées par identifiant CWE.

        Les identifiants invalides sont ignorés. Les identifiants
        valides sont normalisés, dédupliqués et retournés dans
        l'ordre de leur première apparition.

        Une seule lecture groupée du repository est effectuée.
        """
        normalized_cwe_ids = (
            self._normalize_cwe_ids(
                cwe_ids
            )
        )

        if not normalized_cwe_ids:
            return {}

        if (
            len(normalized_cwe_ids)
            > self._max_cwe_ids
        ):
            raise ValueError(
                "cwe_ids exceeds the configured "
                f"limit of {self._max_cwe_ids}"
            )

        # La transaction reste strictement limitée
        # à la lecture groupée du repository.
        with self._unit_of_work as unit_of_work:
            weaknesses = (
                unit_of_work.cwe_weaknesses
                .find_many_by_ids(
                    normalized_cwe_ids
                )
            )

        # La validation métier du résultat est réalisée
        # après la fermeture de la transaction.
        return self._validate_and_order_weaknesses(
            requested_cwe_ids=normalized_cwe_ids,
            weaknesses=weaknesses,
        )

    @classmethod
    def _normalize_cwe_ids(
        cls,
        cwe_ids: Iterable[str | None],
    ) -> list[str]:
        if isinstance(
            cwe_ids,
            (str, bytes),
        ):
            raise TypeError(
                "cwe_ids must be an iterable "
                "of identifiers"
            )

        try:
            iterator = iter(
                cwe_ids
            )

        except TypeError as error:
            raise TypeError(
                "cwe_ids must be iterable"
            ) from error

        normalized_cwe_ids: list[str] = []
        seen: set[str] = set()

        for cwe_id in iterator:
            normalized_cwe_id = (
                cls._normalize_cwe_id(
                    cwe_id
                )
            )

            if normalized_cwe_id is None:
                continue

            if normalized_cwe_id in seen:
                continue

            seen.add(
                normalized_cwe_id
            )

            normalized_cwe_ids.append(
                normalized_cwe_id
            )

        return normalized_cwe_ids

    @classmethod
    def _normalize_cwe_id(
        cls,
        value: object,
    ) -> str | None:
        if not isinstance(value, str):
            return None

        normalized_value = value.strip()

        if (
            not normalized_value
            or len(normalized_value)
            > cls.MAX_CWE_ID_LENGTH
        ):
            return None

        match = _CWE_ID_PATTERN.fullmatch(
            normalized_value
        )

        if match is None:
            return None

        numeric_id = int(
            match.group(1)
        )

        if numeric_id < 1:
            return None

        return f"CWE-{numeric_id}"

    @classmethod
    def _validate_and_order_weaknesses(
        cls,
        *,
        requested_cwe_ids: list[str],
        weaknesses: object,
    ) -> dict[str, CWEWeakness]:
        if not isinstance(
            weaknesses,
            list,
        ):
            raise TypeError(
                "cwe repository result "
                "must be a list"
            )

        requested_cwe_id_set = set(
            requested_cwe_ids
        )

        weaknesses_by_id: dict[
            str,
            CWEWeakness,
        ] = {}

        for weakness in weaknesses:
            if not isinstance(
                weakness,
                CWEWeakness,
            ):
                raise TypeError(
                    "cwe repository values must "
                    "be CWEWeakness instances"
                )

            normalized_cwe_id = (
                cls._normalize_cwe_id(
                    weakness.id
                )
            )

            if normalized_cwe_id is None:
                raise TypeError(
                    "cwe repository returned "
                    "an invalid CWE identifier"
                )

            if weakness.id != normalized_cwe_id:
                raise RuntimeError(
                    "cwe repository returned "
                    "a non-normalized CWE identifier"
                )

            if (
                normalized_cwe_id
                not in requested_cwe_id_set
            ):
                raise RuntimeError(
                    "cwe repository returned "
                    "unexpected CWE identifiers"
                )

            if normalized_cwe_id in weaknesses_by_id:
                raise RuntimeError(
                    "cwe repository returned "
                    "duplicate CWE identifiers"
                )

            weaknesses_by_id[
                normalized_cwe_id
            ] = weakness

        return {
            cwe_id: weaknesses_by_id[cwe_id]
            for cwe_id in requested_cwe_ids
            if cwe_id in weaknesses_by_id
        }

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