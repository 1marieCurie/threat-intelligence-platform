from __future__ import annotations

import uuid
from datetime import date, datetime

from sqlalchemy import (
    CheckConstraint,
    Date,
    DateTime,
    ForeignKey,
    Index,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import (
    ARRAY,
    UUID,
)
from sqlalchemy.orm import (
    Mapped,
    mapped_column,
)

from infrastructure.persistence.models.base import (
    Base,
)


class CisaKevVulnerabilityModel(Base):
    __tablename__ = "cisa_kev_vulnerability"

    __table_args__ = (
        UniqueConstraint(
            "raw_payload_id",
            name="cisa_kev_raw_payload",
        ),
        CheckConstraint(
            "known_ransomware_campaign_use "
            "IN ('known', 'unknown')",
            name="ransomware_campaign_use_valid",
        ),
        Index(
            "ix_cisa_kev_vulnerability_cve_id",
            "cve_id",
        ),
        Index(
            "ix_cisa_kev_vulnerability_due_date",
            "due_date",
        ),
        {
            "schema": "normalized",
        },
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    raw_payload_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey(
            "raw.source_payload.id",
            ondelete="RESTRICT",
        ),
        nullable=False,
    )

    cve_id: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
    )

    vendor_project: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    product: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    vulnerability_name: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    date_added: Mapped[date] = mapped_column(
        Date,
        nullable=False,
    )

    short_description: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    required_action: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    due_date: Mapped[date] = mapped_column(
        Date,
        nullable=False,
    )

    known_ransomware_campaign_use: Mapped[str] = (
        mapped_column(
            String(20),
            nullable=False,
        )
    )

    notes: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    cwes: Mapped[list[str]] = mapped_column(
        ARRAY(
            String(32),
        ),
        nullable=False,
        default=list,
        server_default=text(
            "'{}'::character varying[]"
        ),
    )

    normalizer_version: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
    )

    normalized_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )