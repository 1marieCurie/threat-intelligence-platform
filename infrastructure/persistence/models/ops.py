from __future__ import annotations

import uuid
from datetime import datetime
import sqlalchemy as sa

from sqlalchemy import Boolean, DateTime, String, func
from sqlalchemy.dialects.postgresql import UUID

from sqlalchemy.dialects.postgresql import JSONB

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    func,
)

from sqlalchemy.orm import Mapped, mapped_column

from infrastructure.persistence.models.base import Base


class SourceModel(Base):
    __tablename__ = "source"
    __table_args__ = {
        "schema": "ops",
    }

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    code: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        unique=True,
    )

    name: Mapped[str] = mapped_column(
        String(150),
        nullable=False,
    )

    base_url: Mapped[str | None] = mapped_column(
        String(500),
        nullable=True,
    )

    enabled: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        server_default="true",
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
class IngestionRunModel(Base):
    __tablename__ = "ingestion_run"
    __table_args__ = (
        CheckConstraint(
            "records_received >= 0",
            name="records_received_non_negative",
        ),
        CheckConstraint(
            "records_succeeded >= 0",
            name="records_succeeded_non_negative",
        ),
        CheckConstraint(
            "records_failed >= 0",
            name="records_failed_non_negative",
        ),
        {
            "schema": "ops",
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
        index=True,
    )

    status: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
    )

    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    finished_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    records_received: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default="0",
    )

    records_succeeded: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default="0",
    )

    records_failed: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default="0",
    )

    error_summary: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    connector_version: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )

class SyncStateModel(Base):
    __tablename__ = "sync_state"
    __table_args__ = {
        "schema": "ops",
    }

    source_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey(
            "ops.source.id",
            ondelete="CASCADE",
        ),
        primary_key=True,
    )

    cursor: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    last_success_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    last_attempt_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    metadata_: Mapped[dict[str, object]] = mapped_column(
        "metadata",
        JSONB,
        nullable=False,
        default=dict,
        server_default=sa.text("'{}'::jsonb"),
    )