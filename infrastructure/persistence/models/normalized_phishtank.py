from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
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
    JSONB,
    UUID,
)
from sqlalchemy.orm import (
    Mapped,
    mapped_column,
)

from infrastructure.persistence.models.base import (
    Base,
)


class PhishTankPhishingModel(Base):
    __tablename__ = "phishtank_phishing"

    __table_args__ = (
        UniqueConstraint(
            "raw_payload_id",
            name="phishtank_phishing_raw_payload",
        ),
        CheckConstraint(
            "phish_id > 0",
            name="phish_id_positive",
        ),
        CheckConstraint(
            "char_length(phishing_url) "
            "BETWEEN 1 AND 4096",
            name="phishing_url_length_valid",
        ),
        CheckConstraint(
            "char_length(hostname) "
            "BETWEEN 1 AND 253",
            name="hostname_length_valid",
        ),
        CheckConstraint(
            "jsonb_typeof(network_details) = 'array'",
            name="network_details_array",
        ),
        CheckConstraint(
            "verification_time IS NULL "
            "OR submission_time IS NULL "
            "OR verification_time >= submission_time",
            name="verification_time_order",
        ),
        Index(
            "ix_phishtank_phishing_phish_id",
            "phish_id",
        ),
        Index(
            "ix_phishtank_phishing_hostname",
            "hostname",
        ),
        Index(
            "ix_phishtank_phishing_status",
            "verified",
            "online",
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

    phish_id: Mapped[int] = mapped_column(
        BigInteger,
        nullable=False,
    )

    phishing_url: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    hostname: Mapped[str] = mapped_column(
        String(253),
        nullable=False,
    )

    phish_detail_url: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    submission_time: Mapped[
        datetime | None
    ] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    verification_time: Mapped[
        datetime | None
    ] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    verified: Mapped[bool | None] = mapped_column(
        Boolean,
        nullable=True,
    )

    online: Mapped[bool | None] = mapped_column(
        Boolean,
        nullable=True,
    )

    target: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    network_details: Mapped[
        list[dict[str, object]]
    ] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
        server_default=text(
            "'[]'::jsonb"
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