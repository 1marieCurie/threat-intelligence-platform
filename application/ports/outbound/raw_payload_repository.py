from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol, Sequence
from uuid import UUID


@dataclass(
    frozen=True,
    slots=True,
)
class RawPayloadData:
    source_id: UUID
    ingestion_run_id: UUID
    payload: dict[str, Any]
    payload_hash: str

    external_record_id: str | None = None
    retrieved_at: datetime | None = None
    request_url: str | None = None
    http_status: int | None = None
    source_updated_at: datetime | None = None
    processing_status: str = "pending"
    error_message: str | None = None


@dataclass(
    frozen=True,
    slots=True,
)
class PersistedRawPayload:
    id: UUID
    source_id: UUID
    ingestion_run_id: UUID
    payload: dict[str, Any]
    payload_hash: str
    retrieved_at: datetime
    processing_status: str

    external_record_id: str | None = None
    request_url: str | None = None
    http_status: int | None = None
    source_updated_at: datetime | None = None
    error_message: str | None = None
    processing_started_at: datetime | None = None
    processing_attempts: int = 0


@dataclass(
    frozen=True,
    slots=True,
)
class RawPayloadIdentity:
    """
    Identité immuable d'une version brute.

    Le hash permet de conserver plusieurs versions d'un même
    enregistrement externe.
    """

    source_id: UUID
    external_record_id: str
    payload_hash: str


@dataclass(
    frozen=True,
    slots=True,
)
class PersistedRawPayloadReference:
    """
    Référence vers un payload inséré ou déjà existant.
    """

    payload_id: UUID
    identity: RawPayloadIdentity
    inserted: bool


@dataclass(
    frozen=True,
    slots=True,
)
class RawPayloadBatchSaveResult:
    """
    Résultat d'une écriture raw groupée.

    references contient une entrée par identité unique du lot.
    submitted_count conserve le nombre réel d'éléments reçus,
    doublons internes compris.
    """

    submitted_count: int
    references: tuple[
        PersistedRawPayloadReference,
        ...,
    ]

    @property
    def unique_count(
        self,
    ) -> int:
        return len(
            self.references
        )

    @property
    def inserted_count(
        self,
    ) -> int:
        return sum(
            reference.inserted
            for reference in self.references
        )

    @property
    def existing_count(
        self,
    ) -> int:
        return sum(
            not reference.inserted
            for reference in self.references
        )

    @property
    def duplicate_count(
        self,
    ) -> int:
        return (
            self.submitted_count
            - self.unique_count
        )

    @property
    def skipped_count(
        self,
    ) -> int:
        return (
            self.submitted_count
            - self.inserted_count
        )


@dataclass(
    frozen=True,
    slots=True,
)
class RawPayloadRecoveryResult:
    requeued: int
    failed: int


class RawPayloadRepository(
    Protocol
):
    def save(
        self,
        payload: RawPayloadData,
    ) -> UUID:
        """
        Persiste un payload brut et retourne son identifiant.

        Cette méthode reste disponible pour les écritures isolées.
        """
        ...

    def save_many_ignore_existing(
        self,
        payloads: Sequence[
            RawPayloadData
        ],
    ) -> RawPayloadBatchSaveResult:
        """
        Persiste plusieurs payloads en une opération groupée.

        Les identités déjà présentes sont ignorées sans erreur.
        Le résultat retourne néanmoins leur identifiant existant,
        ce qui permettra de les rattacher ultérieurement à un
        snapshot d'ingestion.
        """
        ...

    def exists_by_identity(
        self,
        *,
        source_id: UUID,
        external_record_id: str | None,
        payload_hash: str,
    ) -> bool:
        """
        Vérifie si une version brute existe déjà.
        """
        ...

    def claim_pending(
        self,
        *,
        source_id: UUID,
        limit: int,
    ) -> Sequence[
        PersistedRawPayload
    ]:
        """
        Réserve atomiquement un lot de payloads en attente.

        Seuls les payloads observés pendant au moins un run
        d'ingestion terminé avec le statut completed sont
        éligibles.

        L'éligibilité repose sur les associations enregistrées
        dans raw.ingestion_run_payload. Elle ne repose pas
        uniquement sur le run ayant créé physiquement le payload,
        car un payload dédupliqué peut être réobservé pendant
        plusieurs runs.

        Les lignes sélectionnées sont immédiatement marquées
        processing dans la transaction courante.
        """
        ...

    def mark_processed(
        self,
        *,
        payload_id: UUID,
    ) -> bool:
        """
        Marque un payload processing comme traité.
        """
        ...

    def mark_failed(
        self,
        *,
        payload_id: UUID,
        error_message: str,
    ) -> bool:
        """
        Marque un payload processing comme échoué.
        """
        ...

    def recover_stale_processing(
        self,
        *,
        source_id: UUID,
        stale_before: datetime,
        max_attempts: int,
        failure_message: str,
    ) -> RawPayloadRecoveryResult:
        """
        Récupère les payloads dont la lease a expiré.

        Les payloads sous la limite sont remis pending. Ceux ayant
        atteint la limite sont définitivement marqués failed.
        """
        ...