from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Protocol

from application.ports.outbound.ingestion_connector import (
    FetchedRecord,
    FetchResult,
)


class PhishTankSnapshotConnector(
    Protocol
):
    """
    Contrat minimal attendu du connecteur de snapshot.

    Ce protocole permet de tester l'adaptateur sans dépendre
    directement du réseau ou du système de fichiers.
    """

    @property
    def canonical_source_url(
        self,
    ) -> str:
        ...

    def download_if_updated(
        self,
        *,
        force: bool = False,
    ) -> dict[str, Any]:
        ...

    def read_local_records(
        self,
        *,
        limit: int | None = None,
    ) -> list[dict[str, Any]]:
        ...


class PhishTankIngestionConnector:
    """
    Adapte le snapshot PhishTank au contrat générique
    d'ingestion brute.

    Responsabilités :

    - déclencher l'actualisation du snapshot local ;
    - lire les enregistrements bruts ;
    - valider les identifiants PhishTank ;
    - convertir chaque enregistrement en FetchedRecord ;
    - exposer uniquement des métadonnées non sensibles.

    Cet adaptateur ne normalise pas les données métier.
    """

    VERSION = "1.0.0"
    SOURCE_NAME = "phishtank"

    def __init__(
        self,
        *,
        connector: PhishTankSnapshotConnector,
        limit: int | None = None,
        force_download: bool = False,
    ) -> None:
        if connector is None:
            raise ValueError(
                "PhishTank connector must not be None."
            )

        self._validate_limit(
            limit
        )

        if not isinstance(
            force_download,
            bool,
        ):
            raise TypeError(
                "force_download must be a boolean."
            )

        self._connector = connector
        self._limit = limit
        self._force_download = (
            force_download
        )

    def fetch(
        self,
        *,
        cursor: str | None,
        state_metadata: (
            dict[str, Any] | None
        ) = None,
    ) -> FetchResult:
        """
        Récupère un snapshot PhishTank.

        PhishTank fournit un snapshot complet et ne possède pas
        de curseur de pagination applicatif.

        Un limit configuré produit volontairement un snapshot
        partiel, principalement destiné aux tests et exécutions
        contrôlées. Cette information est conservée dans les
        métadonnées afin d'empêcher une future réconciliation
        destructive.
        """
        if cursor is not None:
            raise ValueError(
                "PhishTank snapshots do not support cursors."
            )

        # L'ETag et l'état de téléchargement sont actuellement
        # gérés par le connecteur de snapshot local.
        del state_metadata

        synchronization_metadata = (
            self._connector
            .download_if_updated(
                force=self._force_download
            )
        )

        if not isinstance(
            synchronization_metadata,
            dict,
        ):
            raise TypeError(
                "PhishTank synchronization metadata "
                "must be a dictionary."
            )

        raw_records = (
            self._connector
            .read_local_records(
                limit=self._limit
            )
        )

        if not isinstance(
            raw_records,
            list,
        ):
            raise TypeError(
                "PhishTank records must be a list."
            )

        fetched_at = datetime.now(
            UTC
        )

        http_status = (
            200
            if synchronization_metadata.get(
                "downloaded"
            )
            is True
            else None
        )

        records: list[
            FetchedRecord
        ] = []

        seen_phish_ids: set[
            str
        ] = set()

        for index, raw_record in enumerate(
            raw_records
        ):
            if not isinstance(
                raw_record,
                dict,
            ):
                raise ValueError(
                    "Invalid PhishTank record "
                    f"at index {index}: "
                    "expected an object."
                )

            external_record_id = (
                self._extract_phish_id(
                    raw_record,
                    index=index,
                )
            )

            if (
                external_record_id
                in seen_phish_ids
            ):
                raise ValueError(
                    "Invalid PhishTank snapshot: "
                    "duplicate phish identifier."
                )

            records.append(
                FetchedRecord(
                    external_record_id=(
                        external_record_id
                    ),
                    payload=raw_record,
                    source_url=(
                        self._connector
                        .canonical_source_url
                    ),
                    fetched_at=fetched_at,
                    http_status=http_status,
                )
            )

            seen_phish_ids.add(
                external_record_id
            )

        metadata = (
            self._build_metadata(
                synchronization_metadata=(
                    synchronization_metadata
                ),
                records_count=len(
                    records
                ),
            )
        )

        return FetchResult(
            records=tuple(
                records
            ),
            next_cursor=None,
            metadata=metadata,
            connector_version=(
                self.VERSION
            ),
        )

    def _build_metadata(
        self,
        *,
        synchronization_metadata: (
            dict[str, Any]
        ),
        records_count: int,
    ) -> dict[str, Any]:
        """
        Construit une liste blanche de métadonnées.

        Les chemins locaux, clés applicatives et URLs HTTP
        authentifiées ne sont jamais propagés vers PostgreSQL.
        """
        snapshot_complete = (
            self._limit is None
        )

        return {
            "source": self.SOURCE_NAME,
            "source_url": (
                self._connector
                .canonical_source_url
            ),
            "snapshot_format": (
                "online-valid.json.bz2"
            ),
            "snapshot_complete": (
                snapshot_complete
            ),
            "pagination_complete": True,
            "configured_limit": (
                self._limit
            ),
            "records_count": (
                records_count
            ),
            "downloaded": (
                synchronization_metadata.get(
                    "downloaded"
                )
                is True
            ),
            "used_local_snapshot": (
                synchronization_metadata.get(
                    "used_local_snapshot"
                )
                is True
            ),
            "head_request_failed": (
                synchronization_metadata.get(
                    "head_request_failed"
                )
                is True
            ),
            "etag": (
                self._clean_optional_string(
                    synchronization_metadata.get(
                        "etag"
                    )
                )
            ),
            "last_modified": (
                self._clean_optional_string(
                    synchronization_metadata.get(
                        "last_modified"
                    )
                )
            ),
            "content_length": (
                self._clean_content_length(
                    synchronization_metadata.get(
                        "content_length"
                    )
                )
            ),
            "snapshot_downloaded_at": (
                self._clean_optional_string(
                    synchronization_metadata.get(
                        "downloaded_at"
                    )
                )
            ),
        }

    @staticmethod
    def _extract_phish_id(
        raw_record: dict[str, Any],
        *,
        index: int,
    ) -> str:
        """
        Extrait et normalise un identifiant PhishTank positif.
        """
        value = raw_record.get(
            "phish_id"
        )

        if (
            isinstance(value, bool)
            or value is None
        ):
            raise ValueError(
                "Invalid PhishTank record "
                f"at index {index}: "
                "phish_id must be a positive integer."
            )

        if isinstance(
            value,
            int,
        ):
            parsed_value = value

        elif isinstance(
            value,
            str,
        ):
            normalized_value = (
                value.strip()
            )

            if not normalized_value.isdigit():
                raise ValueError(
                    "Invalid PhishTank record "
                    f"at index {index}: "
                    "phish_id must be a positive integer."
                )

            parsed_value = int(
                normalized_value
            )

        else:
            raise ValueError(
                "Invalid PhishTank record "
                f"at index {index}: "
                "phish_id must be a positive integer."
            )

        if parsed_value <= 0:
            raise ValueError(
                "Invalid PhishTank record "
                f"at index {index}: "
                "phish_id must be a positive integer."
            )

        return str(
            parsed_value
        )

    @staticmethod
    def _clean_optional_string(
        value: Any,
    ) -> str | None:
        if not isinstance(
            value,
            str,
        ):
            return None

        normalized = value.strip()

        return (
            normalized
            or None
        )

    @staticmethod
    def _clean_content_length(
        value: Any,
    ) -> int | None:
        if (
            isinstance(value, bool)
            or not isinstance(
                value,
                int,
            )
            or value < 0
        ):
            return None

        return value

    @staticmethod
    def _validate_limit(
        value: int | None,
    ) -> None:
        if value is None:
            return

        if (
            isinstance(value, bool)
            or not isinstance(
                value,
                int,
            )
        ):
            raise TypeError(
                "limit must be an integer or None."
            )

        if value < 0:
            raise ValueError(
                "limit must be greater than "
                "or equal to zero."
            )