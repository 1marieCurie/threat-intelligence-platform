from __future__ import annotations

import uuid
from datetime import datetime
from decimal import Decimal

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    Numeric,
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


class MLURLSampleModel(Base):
    __tablename__ = "url_sample"

    __table_args__ = (
        UniqueConstraint(
            "canonicalization_version",
            "value_hash",
            name="uq_ml_url_sample_identity",
        ),
        CheckConstraint(
            "value_hash ~ '^[a-f0-9]{64}$'",
            name="hash_valid",
        ),
        CheckConstraint(
            "canonicalization_version > 0",
            name="version_positive",
        ),
        CheckConstraint(
            "char_length(hostname) "
            "BETWEEN 1 AND 253",
            name="hostname_valid",
        ),
        CheckConstraint(
            "source ~ '^[a-z][a-z0-9_]*$'",
            name="source_valid",
        ),
        CheckConstraint(
            "jsonb_typeof(source_metadata) "
            "= 'object'",
            name="metadata_object",
        ),
        Index(
            "ix_ml_url_sample_hostname",
            "hostname",
        ),
        Index(
            "ix_ml_url_sample_canonical_indicator",
            "canonical_web_indicator_id",
        ),
        {"schema": "ml"},
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    canonical_web_indicator_id: Mapped[
        uuid.UUID | None
    ] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey(
            "canonical."
            "canonical_web_indicator.id",
            ondelete="SET NULL",
        ),
        nullable=True,
    )

    value_hash: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )

    hostname: Mapped[str] = mapped_column(
        String(253),
        nullable=False,
    )

    canonicalization_version: Mapped[int] = (
        mapped_column(
            Integer,
            nullable=False,
        )
    )

    source: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )

    source_metadata: Mapped[
        dict[str, object]
    ] = mapped_column(
        JSONB,
        nullable=False,
        server_default=text(
            "'{}'::jsonb"
        ),
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )


class MLURLProjectionModel(Base):
    __tablename__ = "url_projection"

    __table_args__ = (
        CheckConstraint(
            "char_length(projection_version) "
            "BETWEEN 1 AND 30",
            name="projection_version_valid",
        ),
        CheckConstraint(
            "char_length(model_value) "
            "BETWEEN 1 AND 4096",
            name="model_value_valid",
        ),
        {"schema": "ml"},
    )

    sample_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey(
            "ml.url_sample.id",
            ondelete="CASCADE",
        ),
        primary_key=True,
    )

    projection_version: Mapped[str] = (
        mapped_column(
            String(30),
            primary_key=True,
        )
    )

    model_value: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )


class MLURLFeatureVectorModel(Base):
    __tablename__ = "url_feature_vector"

    __table_args__ = (
        CheckConstraint(
            "char_length(feature_set_version) "
            "BETWEEN 1 AND 30",
            name="feature_set_version_valid",
        ),
        CheckConstraint(
            "jsonb_typeof(features) = 'object'",
            name="features_object",
        ),
        CheckConstraint(
            "features <> '{}'::jsonb",
            name="features_not_empty",
        ),
        {"schema": "ml"},
    )

    sample_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey(
            "ml.url_sample.id",
            ondelete="CASCADE",
        ),
        primary_key=True,
    )

    feature_set_version: Mapped[str] = (
        mapped_column(
            String(30),
            primary_key=True,
        )
    )

    features: Mapped[
        dict[str, int | float]
    ] = mapped_column(
        JSONB,
        nullable=False,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )


class MLURLSampleLabelModel(Base):
    __tablename__ = "url_sample_label"

    __table_args__ = (
        UniqueConstraint(
            "sample_id",
            "label_code",
            "label_source",
            name="uq_ml_sample_label_source",
        ),
        CheckConstraint(
            "label_code "
            "~ '^[a-z][a-z0-9_]*$'",
            name="label_code_valid",
        ),
        CheckConstraint(
            "label_source "
            "~ '^[a-z][a-z0-9_]*$'",
            name="label_source_valid",
        ),
        CheckConstraint(
            "confidence >= 0 "
            "AND confidence <= 1",
            name="confidence_valid",
        ),
        Index(
            "ix_ml_sample_label_code",
            "label_code",
        ),
        {"schema": "ml"},
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    sample_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey(
            "ml.url_sample.id",
            ondelete="CASCADE",
        ),
        nullable=False,
    )

    label_code: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )

    label_source: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )

    confidence: Mapped[Decimal] = mapped_column(
        Numeric(5, 4),
        nullable=False,
    )

    observed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )


class MLDatasetSnapshotModel(Base):
    __tablename__ = "dataset_snapshot"

    __table_args__ = (
        UniqueConstraint(
            "name",
            "version",
            name="uq_ml_dataset_snapshot_version",
        ),
        CheckConstraint(
            "status IN ('draft', 'frozen')",
            name="status_valid",
        ),
        CheckConstraint(
            "feature_set_version IS NULL "
            "OR char_length(feature_set_version) "
            "BETWEEN 1 AND 30",
            name="feature_set_version_valid",
        ),
        CheckConstraint(
            "jsonb_typeof(class_targets) "
            "= 'object'",
            name="targets_object",
        ),
        CheckConstraint(
            "jsonb_typeof(label_mapping) "
            "= 'object'",
            name="mapping_object",
        ),
        CheckConstraint(
            "jsonb_typeof(selection_config) "
            "= 'object'",
            name="config_object",
        ),
        CheckConstraint(
            "jsonb_typeof(source_manifest) "
            "= 'object'",
            name="manifest_object",
        ),
        {"schema": "ml"},
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    name: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    version: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )

    status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        server_default=text(
            "'draft'"
        ),
    )

    projection_version: Mapped[str] = (
        mapped_column(
            String(30),
            nullable=False,
        )
    )

    feature_set_version: Mapped[
        str | None
    ] = mapped_column(
        String(30),
        nullable=True,
    )

    class_targets: Mapped[
        dict[str, object]
    ] = mapped_column(
        JSONB,
        nullable=False,
    )

    label_mapping: Mapped[
        dict[str, object]
    ] = mapped_column(
        JSONB,
        nullable=False,
    )

    selection_config: Mapped[
        dict[str, object]
    ] = mapped_column(
        JSONB,
        nullable=False,
    )

    source_manifest: Mapped[
        dict[str, object]
    ] = mapped_column(
        JSONB,
        nullable=False,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    frozen_at: Mapped[
        datetime | None
    ] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )


class MLDatasetMemberModel(Base):
    __tablename__ = "dataset_member"

    __table_args__ = (
        CheckConstraint(
            "label_code "
            "~ '^[a-z][a-z0-9_]*$'",
            name="label_code_valid",
        ),
        CheckConstraint(
            "split IS NULL OR split IN "
            "('train', 'validation', 'test')",
            name="split_valid",
        ),
        CheckConstraint(
            "char_length(group_key) "
            "BETWEEN 1 AND 253",
            name="group_key_valid",
        ),
        Index(
            "ix_ml_member_label",
            "dataset_id",
            "label_code",
        ),
        Index(
            "ix_ml_member_group",
            "dataset_id",
            "group_key",
        ),
        {"schema": "ml"},
    )

    dataset_id: Mapped[
        uuid.UUID
    ] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey(
            "ml.dataset_snapshot.id",
            ondelete="CASCADE",
        ),
        primary_key=True,
    )

    sample_id: Mapped[
        uuid.UUID
    ] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey(
            "ml.url_sample.id",
            ondelete="CASCADE",
        ),
        primary_key=True,
    )

    label_code: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )

    split: Mapped[
        str | None
    ] = mapped_column(
        String(20),
        nullable=True,
    )

    group_key: Mapped[str] = mapped_column(
        String(253),
        nullable=False,
    )

    selected_at: Mapped[
        datetime
    ] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )