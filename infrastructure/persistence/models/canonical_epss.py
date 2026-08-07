from __future__ import annotations

from datetime import (
    date,
    datetime,
)
from uuid import UUID

from sqlalchemy import (
    CheckConstraint,
    Date,
    DateTime,
    Float,
    ForeignKey,
    Index,
    String,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import (
    UUID as PostgreSQLUUID,
)
from sqlalchemy.orm import (
    Mapped,
    mapped_column,
)

from infrastructure.persistence.models.base import (
    Base,
)


class CanonicalVulnerabilityEPSSModel(Base):
    """
    Dernier snapshot EPSS connu pour une vulnérabilité.

    L'absence d'une ligne signifie que le score est inconnu.
    Elle ne signifie jamais que la vulnérabilité doit être
    exclue de la couche canonique.
    """

    __tablename__ = (
        "canonical_vulnerability_epss"
    )

    __table_args__ = (
        CheckConstraint(
            (
                "score >= 0 "
                "AND score <= 1"
            ),
            name=(
                "ck_canonical_vulnerability_"
                "epss_score_range"
            ),
        ),
        CheckConstraint(
            (
                "percentile >= 0 "
                "AND percentile <= 1"
            ),
            name=(
                "ck_canonical_vulnerability_"
                "epss_percentile_range"
            ),
        ),
        CheckConstraint(
            (
                "cve_id ~ "
                "'^CVE-[0-9]{4}-"
                "[0-9]{4,19}$'"
            ),
            name=(
                "ck_canonical_vulnerability_"
                "epss_cve_id_valid"
            ),
        ),
        UniqueConstraint(
            "cve_id",
            name=(
                "uq_canonical_vulnerability_"
                "epss_cve_id"
            ),
        ),
        Index(
            (
                "ix_canonical_vulnerability_"
                "epss_score"
            ),
            "score",
        ),
        Index(
            (
                "ix_canonical_vulnerability_"
                "epss_score_date"
            ),
            "score_date",
        ),
        {
            "schema": "canonical",
        },
    )

    vulnerability_id: Mapped[UUID] = (
        mapped_column(
            PostgreSQLUUID(as_uuid=True),
            ForeignKey(
                (
                    "canonical."
                    "canonical_vulnerability.id"
                ),
                name=(
                    "fk_canonical_vulnerability_"
                    "epss_vulnerability_id"
                ),
                ondelete="CASCADE",
            ),
            primary_key=True,
            nullable=False,
        )
    )

    cve_id: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
    )

    score: Mapped[float] = mapped_column(
        Float,
        nullable=False,
    )

    percentile: Mapped[float] = (
        mapped_column(
            Float,
            nullable=False,
        )
    )

    score_date: Mapped[date] = (
        mapped_column(
            Date,
            nullable=False,
        )
    )

    api_version: Mapped[str | None] = (
        mapped_column(
            String(20),
            nullable=True,
        )
    )

    synchronized_at: Mapped[datetime] = (
        mapped_column(
            DateTime(timezone=True),
            nullable=False,
        )
    )

    updated_at: Mapped[datetime] = (
        mapped_column(
            DateTime(timezone=True),
            nullable=False,
            server_default=text("now()"),
        )
    )