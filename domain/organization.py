from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from domain._asset_validation import (
    normalize_datetime_utc,
    normalize_required_text,
    validate_bool,
    validate_uuid,
)


_SLUG_PATTERN = re.compile(
    r"^[a-z0-9]+(?:-[a-z0-9]+)*$"
)


@dataclass(
    frozen=True,
    slots=True,
)
class Organization:
    id: UUID
    name: str
    is_active: bool
    created_at: datetime

    # Valeur par défaut conservée temporairement
    # pour ne pas casser les anciens chemins métier
    # qui construisent encore Organization sans slug.
    slug: str = ""

    def __post_init__(
        self,
    ) -> None:
        object.__setattr__(
            self,
            "id",
            validate_uuid(
                self.id,
                field_name="id",
            ),
        )

        object.__setattr__(
            self,
            "name",
            normalize_required_text(
                self.name,
                field_name="name",
            ),
        )

        object.__setattr__(
            self,
            "is_active",
            validate_bool(
                self.is_active,
                field_name="is_active",
            ),
        )

        object.__setattr__(
            self,
            "created_at",
            normalize_datetime_utc(
                self.created_at,
                field_name="created_at",
            ),
        )

        object.__setattr__(
            self,
            "slug",
            self._normalize_slug(
                self.slug
            ),
        )

    @staticmethod
    def _normalize_slug(
        value: str,
    ) -> str:
        if not isinstance(
            value,
            str,
        ):
            raise TypeError(
                "slug must be a string"
            )

        normalized = (
            value.strip().lower()
        )

        # Compatibilité avec les anciens usages
        # d'Organization qui ne fournissent pas
        # encore de slug.
        if not normalized:
            return ""

        if len(normalized) > 63:
            raise ValueError(
                (
                    "slug must not exceed "
                    "63 characters"
                )
            )

        if (
            _SLUG_PATTERN.fullmatch(
                normalized
            )
            is None
        ):
            raise ValueError(
                (
                    "slug must contain only "
                    "lowercase letters, digits "
                    "and single hyphens between "
                    "segments"
                )
            )

        return normalized