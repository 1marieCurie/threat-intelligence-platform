from __future__ import annotations

from dataclasses import dataclass
from datetime import (
    UTC,
    datetime,
)
from uuid import UUID

from domain.cwe_identifier import (
    normalize_cwe_ids,
)
from domain.vulnerability_identifier import (
    VulnerabilityIdentifier,
)


@dataclass(
    frozen=True,
    slots=True,
)
class GitHubAdvisoryCanonicalCursor:
    """
    Curseur SQL stable de pagination GitHub Advisory.

    ghsa_id conserve exactement la casse présente dans
    la table normalisée. Il ne représente pas la valeur
    canonique utilisée par le domaine.
    """

    ghsa_id: str
    normalized_record_id: UUID

    def __post_init__(self) -> None:
        if not isinstance(
            self.normalized_record_id,
            UUID,
        ):
            raise TypeError(
                "normalized_record_id must be a UUID"
            )

        if not isinstance(
            self.ghsa_id,
            str,
        ):
            raise TypeError(
                "ghsa_id must be a string"
            )

        storage_ghsa_id = self.ghsa_id.strip()

        # Valide le format sans remplacer la casse exacte
        # utilisée pour la pagination SQL.
        VulnerabilityIdentifier(
            namespace="GHSA",
            value=storage_ghsa_id,
            is_primary=True,
        )

        object.__setattr__(
            self,
            "ghsa_id",
            storage_ghsa_id,
        )


@dataclass(
    frozen=True,
    slots=True,
)
class GitHubAdvisoryCanonicalSourceRecord:
    """
    Projection minimale d'un GitHub Security Advisory normalisé.

    Cette projection est utilisée pour :
    - la corrélation canonique ;
    - l'enrichissement relationnel CWE.

    ghsa_id contient l'identifiant canonique uppercase.

    source_ghsa_id conserve la valeur exacte provenant
    de PostgreSQL pour construire le curseur keyset.

    Les identifiants CWE sont uniquement des références
    fournisseur. Leur présence dans le catalogue officiel
    doit être validée séparément par CWELookupService.
    """

    normalized_record_id: UUID
    ghsa_id: str
    normalized_at: datetime

    cve_id: str | None = None
    cwe_ids: tuple[str, ...] = ()

    published_at: datetime | None = None
    updated_at: datetime | None = None
    withdrawn_at: datetime | None = None

    source_ghsa_id: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(
            self.normalized_record_id,
            UUID,
        ):
            raise TypeError(
                "normalized_record_id must be a UUID"
            )

        canonical_ghsa_id = (
            VulnerabilityIdentifier(
                namespace="GHSA",
                value=self.ghsa_id,
                is_primary=True,
            ).value
        )

        source_ghsa_id = (
            self.ghsa_id
            if self.source_ghsa_id is None
            else self.source_ghsa_id
        )

        source_cursor = (
            GitHubAdvisoryCanonicalCursor(
                ghsa_id=source_ghsa_id,
                normalized_record_id=(
                    self.normalized_record_id
                ),
            )
        )

        source_canonical_ghsa_id = (
            VulnerabilityIdentifier(
                namespace="GHSA",
                value=source_cursor.ghsa_id,
                is_primary=True,
            ).value
        )

        if (
            source_canonical_ghsa_id
            != canonical_ghsa_id
        ):
            raise ValueError(
                "source_ghsa_id and ghsa_id "
                "must identify the same advisory"
            )

        normalized_cve_id = (
            None
            if self.cve_id is None
            else VulnerabilityIdentifier(
                namespace="CVE",
                value=self.cve_id,
                is_primary=True,
            ).value
        )

        normalized_cwe_ids = normalize_cwe_ids(
            self.cwe_ids
        )

        normalized_at = (
            self._normalize_datetime(
                self.normalized_at,
                field_name="normalized_at",
            )
        )

        published_at = (
            self._normalize_optional_datetime(
                self.published_at,
                field_name="published_at",
            )
        )

        updated_at = (
            self._normalize_optional_datetime(
                self.updated_at,
                field_name="updated_at",
            )
        )

        withdrawn_at = (
            self._normalize_optional_datetime(
                self.withdrawn_at,
                field_name="withdrawn_at",
            )
        )

        object.__setattr__(
            self,
            "ghsa_id",
            canonical_ghsa_id,
        )

        object.__setattr__(
            self,
            "source_ghsa_id",
            source_cursor.ghsa_id,
        )

        object.__setattr__(
            self,
            "cve_id",
            normalized_cve_id,
        )

        object.__setattr__(
            self,
            "cwe_ids",
            normalized_cwe_ids,
        )

        object.__setattr__(
            self,
            "normalized_at",
            normalized_at,
        )

        object.__setattr__(
            self,
            "published_at",
            published_at,
        )

        object.__setattr__(
            self,
            "updated_at",
            updated_at,
        )

        object.__setattr__(
            self,
            "withdrawn_at",
            withdrawn_at,
        )

    @property
    def cursor(
        self,
    ) -> GitHubAdvisoryCanonicalCursor:
        source_ghsa_id = self.source_ghsa_id

        if source_ghsa_id is None:
            raise RuntimeError(
                "source_ghsa_id invariant violated"
            )

        return GitHubAdvisoryCanonicalCursor(
            ghsa_id=source_ghsa_id,
            normalized_record_id=(
                self.normalized_record_id
            ),
        )

    @property
    def is_withdrawn(self) -> bool:
        return self.withdrawn_at is not None

    @staticmethod
    def _normalize_datetime(
        value: datetime,
        *,
        field_name: str,
    ) -> datetime:
        if not isinstance(
            value,
            datetime,
        ):
            raise TypeError(
                f"{field_name} must be a datetime"
            )

        if (
            value.tzinfo is None
            or value.utcoffset() is None
        ):
            raise ValueError(
                f"{field_name} must be "
                "timezone-aware"
            )

        return value.astimezone(
            UTC
        )

    @classmethod
    def _normalize_optional_datetime(
        cls,
        value: datetime | None,
        *,
        field_name: str,
    ) -> datetime | None:
        if value is None:
            return None

        return cls._normalize_datetime(
            value,
            field_name=field_name,
        )