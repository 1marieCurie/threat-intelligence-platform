from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import (
    DOUBLE_PRECISION,
    UUID,
)
from sqlalchemy.orm import (
    Mapped,
    mapped_column,
)

from infrastructure.persistence.models.base import (
    Base,
)


class CanonicalVulnerabilityModel(Base):
    __tablename__ = "canonical_vulnerability"

    __table_args__ = (
        CheckConstraint(
            "status IN ("
            "'provisional', "
            "'active', "
            "'withdrawn', "
            "'rejected', "
            "'merged'"
            ")",
            name="status_valid",
        ),
        CheckConstraint(
            "correlation_version > 0",
            name="correlation_version_positive",
        ),
        CheckConstraint(
            "updated_at >= created_at",
            name="timestamps_order",
        ),
        CheckConstraint(
            "("
            "status = 'merged' "
            "AND merged_into_id IS NOT NULL"
            ") OR ("
            "status <> 'merged' "
            "AND merged_into_id IS NULL"
            ")",
            name="merge_target_consistent",
        ),
        CheckConstraint(
            "merged_into_id IS NULL "
            "OR merged_into_id <> id",
            name="merge_target_not_self",
        ),
        Index(
            "ix_canonical_vulnerability_updated_at",
            "updated_at",
        ),
        Index(
            "ix_canonical_vulnerability_merged_into_id",
            "merged_into_id",
        ),
        {
            "schema": "canonical",
        },
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(
            as_uuid=True,
        ),
        primary_key=True,
        default=uuid.uuid4,
    )

    status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="provisional",
        server_default=text(
            "'provisional'"
        ),
    )

    correlation_version: Mapped[int] = (
        mapped_column(
            Integer,
            nullable=False,
            default=1,
            server_default=text("1"),
        )
    )

    merged_into_id: Mapped[
        uuid.UUID | None
    ] = mapped_column(
        UUID(
            as_uuid=True,
        ),
        ForeignKey(
            "canonical."
            "canonical_vulnerability.id",
            ondelete="RESTRICT",
        ),
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(
            timezone=True,
        ),
        nullable=False,
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(
            timezone=True,
        ),
        nullable=False,
    )


class CanonicalVulnerabilityIdentifierModel(
    Base
):
    __tablename__ = (
        "canonical_vulnerability_identifier"
    )

    __table_args__ = (
        UniqueConstraint(
            "namespace",
            "value",
            name=(
                "canonical_identifier_"
                "namespace_value"
            ),
        ),
        CheckConstraint(
            "namespace IN ('CVE', 'GHSA')",
            name="namespace_valid",
        ),
        CheckConstraint(
            "("
            "namespace = 'CVE' "
            "AND value ~ "
            "'^CVE-[0-9]{4}-[0-9]{4,19}$'"
            ") OR ("
            "namespace = 'GHSA' "
            "AND value ~ "
            "'^GHSA-[A-Z0-9]{4}-"
            "[A-Z0-9]{4}-"
            "[A-Z0-9]{4}$'"
            ")",
            name="value_format_valid",
        ),
        Index(
            "ix_canonical_identifier_"
            "vulnerability_id",
            "vulnerability_id",
        ),
        Index(
            "uq_canonical_vulnerability_"
            "primary_identifier",
            "vulnerability_id",
            unique=True,
            postgresql_where=text(
                "is_primary IS TRUE"
            ),
        ),
        {
            "schema": "canonical",
        },
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(
            as_uuid=True,
        ),
        primary_key=True,
        default=uuid.uuid4,
    )

    vulnerability_id: Mapped[
        uuid.UUID
    ] = mapped_column(
        UUID(
            as_uuid=True,
        ),
        ForeignKey(
            "canonical."
            "canonical_vulnerability.id",
            ondelete="CASCADE",
        ),
        nullable=False,
    )

    namespace: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
    )

    value: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )

    is_primary: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default=text("false"),
    )


class CanonicalVulnerabilityEvidenceModel(
    Base
):
    __tablename__ = (
        "canonical_vulnerability_evidence"
    )

    __table_args__ = (
        UniqueConstraint(
            "source",
            "source_record_key",
            name=(
                "canonical_evidence_"
                "source_record"
            ),
        ),
        CheckConstraint(
            "source ~ '^[a-z][a-z0-9_]*$'",
            name="source_format_valid",
        ),
        CheckConstraint(
            "evidence_type "
            "~ '^[a-z][a-z0-9_]*$'",
            name="evidence_type_format_valid",
        ),
        CheckConstraint(
            "correlation_rule "
            "~ '^[a-z][a-z0-9_]*$'",
            name=(
                "correlation_rule_"
                "format_valid"
            ),
        ),
        CheckConstraint(
            "correlation_confidence >= 0 "
            "AND correlation_confidence <= 1",
            name=(
                "correlation_confidence_"
                "range"
            ),
        ),
        CheckConstraint(
            "record_hash IS NULL "
            "OR record_hash "
            "~ '^[a-f0-9]{64}$'",
            name="record_hash_format_valid",
        ),
        CheckConstraint(
            "btrim(source_record_key) <> ''",
            name="source_record_key_not_empty",
        ),
        CheckConstraint(
            "btrim(normalized_record_id) <> ''",
            name=(
                "normalized_record_id_"
                "not_empty"
            ),
        ),
        CheckConstraint(
            "last_observed_at >= observed_at",
            name="observation_dates_order",
        ),
        Index(
            "ix_canonical_evidence_"
            "vulnerability_id",
            "vulnerability_id",
        ),
        Index(
            "ix_canonical_evidence_"
            "last_observed_at",
            "last_observed_at",
        ),
        {
            "schema": "canonical",
        },
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(
            as_uuid=True,
        ),
        primary_key=True,
        default=uuid.uuid4,
    )

    vulnerability_id: Mapped[
        uuid.UUID
    ] = mapped_column(
        UUID(
            as_uuid=True,
        ),
        ForeignKey(
            "canonical."
            "canonical_vulnerability.id",
            ondelete="CASCADE",
        ),
        nullable=False,
    )

    source: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )

    source_record_key: Mapped[str] = (
        mapped_column(
            String(255),
            nullable=False,
        )
    )

    normalized_record_id: Mapped[str] = (
        mapped_column(
            String(255),
            nullable=False,
        )
    )

    evidence_type: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )

    correlation_rule: Mapped[str] = (
        mapped_column(
            String(64),
            nullable=False,
        )
    )

    observed_at: Mapped[datetime] = (
        mapped_column(
            DateTime(
                timezone=True,
            ),
            nullable=False,
        )
    )

    last_observed_at: Mapped[datetime] = (
        mapped_column(
            DateTime(
                timezone=True,
            ),
            nullable=False,
        )
    )

    source_published_at: Mapped[
        datetime | None
    ] = mapped_column(
        DateTime(
            timezone=True,
        ),
        nullable=True,
    )

    source_modified_at: Mapped[
        datetime | None
    ] = mapped_column(
        DateTime(
            timezone=True,
        ),
        nullable=True,
    )

    correlation_confidence: Mapped[
        float
    ] = mapped_column(
        DOUBLE_PRECISION,
        nullable=False,
        default=1.0,
        server_default=text("1"),
    )

    record_hash: Mapped[
        str | None
    ] = mapped_column(
        String(64),
        nullable=True,
    )