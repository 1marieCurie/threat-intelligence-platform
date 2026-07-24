from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from infrastructure.persistence.models.base import Base


class SourcePayloadModel(Base):
    __tablename__ = "source_payload"
    __table_args__ = (
        CheckConstraint(
            "http_status IS NULL OR "
            "(http_status >= 100 AND http_status <= 599)",
            name="http_status_valid",
        ),
        UniqueConstraint(
            "source_id",
            "external_record_id",
            "payload_hash",
            name="source_external_id_payload_hash",
        ),
        Index(
            "ix_source_payload_source_retrieved_at",
            "source_id",
            "retrieved_at",
        ),
        Index(
            "ix_source_payload_ingestion_run_id",
            "ingestion_run_id",
        ),
        {
            "schema": "raw",
        },
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    source_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey(
            "ops.source.id",
            ondelete="RESTRICT",
        ),
        nullable=False,
    )

    ingestion_run_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey(
            "ops.ingestion_run.id",
            ondelete="RESTRICT",
        ),
        nullable=False,
    )

    external_record_id: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    retrieved_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    request_url: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    http_status: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )

    payload: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
    )

    payload_hash: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )

    source_updated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    processing_status: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        server_default=text("'pending'"),
    )

    error_message: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )