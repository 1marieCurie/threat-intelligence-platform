from __future__ import annotations

from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from typing import Any

from application.ports.outbound.cwe_catalog_client import (
    CWECatalogClient,
)
from application.ports.outbound.cwe_catalog_sync_unit_of_work import (
    CWECatalogSyncUnitOfWork,
)
from application.services.cwe_weakness_mapper import (
    CWEWeaknessMapper,
)


@dataclass(
    frozen=True,
    slots=True,
)
class CWECatalogSyncResult:
    catalog_version: str | None
    catalog_date: str | None

    requested_ids: int
    fetched_weaknesses: int
    persisted_weaknesses: int
    batches: int

    missing_ids: tuple[str, ...] = ()


class CWECatalogSyncService:
    """
    Synchronise les CWE référencés par les vulnérabilités.

    Les opérations réseau sont exécutées hors transaction.
    Chaque lot est persisté dans une transaction PostgreSQL courte.
    """

    MAX_BATCH_SIZE = 50
    DEFAULT_BATCH_SIZE = 50
    DEFAULT_MAX_CWE_IDS = 5_000

    def __init__(
        self,
        *,
        client: CWECatalogClient,
        unit_of_work: CWECatalogSyncUnitOfWork,
        batch_size: int = DEFAULT_BATCH_SIZE,
        max_cwe_ids: int = DEFAULT_MAX_CWE_IDS,
    ) -> None:
        if client is None:
            raise ValueError(
                "client is required"
            )

        if unit_of_work is None:
            raise ValueError(
                "unit_of_work is required"
            )

        self._validate_positive_integer(
            batch_size,
            field_name="batch_size",
        )

        self._validate_positive_integer(
            max_cwe_ids,
            field_name="max_cwe_ids",
        )

        if batch_size > self.MAX_BATCH_SIZE:
            raise ValueError(
                "batch_size must not exceed 50"
            )

        self._client = client
        self._unit_of_work = unit_of_work
        self._batch_size = batch_size
        self._max_cwe_ids = max_cwe_ids

    def synchronize_referenced(
        self,
    ) -> CWECatalogSyncResult:
        """
        Synchronise les identifiants CWE présents dans CISA et GHAD.
        """

        cwe_ids = self._load_referenced_ids()

        if not cwe_ids:
            return CWECatalogSyncResult(
                catalog_version=None,
                catalog_date=None,
                requested_ids=0,
                fetched_weaknesses=0,
                persisted_weaknesses=0,
                batches=0,
            )

        version_payload = (
            self._client.fetch_version()
        )

        catalog_version, catalog_date = (
            self._parse_version(
                version_payload
            )
        )

        fetched_weaknesses = 0
        persisted_weaknesses = 0
        batches = 0

        missing_ids: set[str] = set()

        for batch in self._chunked(
            cwe_ids,
            self._batch_size,
        ):
            # L'appel HTTP est volontairement effectué
            # en dehors d'une transaction PostgreSQL.
            payload = (
                self._client.fetch_weaknesses(
                    batch
                )
            )

            weaknesses = (
                CWEWeaknessMapper.map_payload(
                    payload,
                    catalog_version=(
                        catalog_version
                    ),
                    catalog_date=catalog_date,
                )
            )

            requested_batch_ids = set(
                batch
            )

            returned_ids = {
                weakness.id
                for weakness in weaknesses
            }

            unexpected_ids = (
                returned_ids
                - requested_batch_ids
            )

            if unexpected_ids:
                raise ValueError(
                    "MITRE returned unexpected CWE "
                    "identifiers"
                )

            missing_ids.update(
                requested_batch_ids
                - returned_ids
            )

            if weaknesses:
                with self._unit_of_work as uow:
                    persisted_count = (
                        uow.cwe_weaknesses
                        .upsert_many(
                            weaknesses
                        )
                    )

                    uow.commit()

                persisted_weaknesses += (
                    persisted_count
                )

            fetched_weaknesses += len(
                weaknesses
            )

            batches += 1

        return CWECatalogSyncResult(
            catalog_version=catalog_version,
            catalog_date=catalog_date,
            requested_ids=len(
                cwe_ids
            ),
            fetched_weaknesses=(
                fetched_weaknesses
            ),
            persisted_weaknesses=(
                persisted_weaknesses
            ),
            batches=batches,
            missing_ids=tuple(
                sorted(
                    missing_ids,
                    key=self._cwe_sort_key,
                )
            ),
        )

    def _load_referenced_ids(
        self,
    ) -> list[str]:
        """
        Charge les identifiants avec une limite stricte.

        Une valeur supplémentaire est demandée pour détecter un
        dépassement sans charger un volume non borné.
        """

        with self._unit_of_work as uow:
            values = (
                uow
                .vulnerability_cwe_references
                .list_distinct_ids(
                    limit=(
                        self._max_cwe_ids
                        + 1
                    )
                )
            )

        if len(values) > self._max_cwe_ids:
            raise RuntimeError(
                "Referenced CWE identifier limit "
                "was exceeded"
            )

        return values

    @staticmethod
    def _parse_version(
        payload: Mapping[str, Any],
    ) -> tuple[
        str | None,
        str | None,
    ]:
        if not isinstance(
            payload,
            Mapping,
        ):
            raise TypeError(
                "version payload must be a mapping"
            )

        version = (
            CWECatalogSyncService
            ._optional_text(
                payload.get(
                    "ContentVersion"
                ),
                field_name=(
                    "ContentVersion"
                ),
            )
        )

        catalog_date = (
            CWECatalogSyncService
            ._optional_text(
                payload.get(
                    "ContentDate"
                ),
                field_name="ContentDate",
            )
        )

        return version, catalog_date

    @staticmethod
    def _optional_text(
        value: Any,
        *,
        field_name: str,
    ) -> str | None:
        if value is None:
            return None

        if not isinstance(
            value,
            str,
        ):
            raise ValueError(
                f"{field_name} must be a string"
            )

        normalized = value.strip()

        return normalized or None

    @staticmethod
    def _validate_positive_integer(
        value: int,
        *,
        field_name: str,
    ) -> None:
        if isinstance(
            value,
            bool,
        ):
            raise TypeError(
                f"{field_name} must be an integer"
            )

        if not isinstance(
            value,
            int,
        ):
            raise TypeError(
                f"{field_name} must be an integer"
            )

        if value <= 0:
            raise ValueError(
                f"{field_name} must be greater "
                "than zero"
            )

    @staticmethod
    def _chunked(
        values: list[str],
        size: int,
    ) -> Iterator[list[str]]:
        for start in range(
            0,
            len(values),
            size,
        ):
            yield values[
                start:start + size
            ]

    @staticmethod
    def _cwe_sort_key(
        cwe_id: str,
    ) -> int:
        return int(
            cwe_id.removeprefix(
                "CWE-"
            )
        )