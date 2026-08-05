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
    Text,
    UniqueConstraint,
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


class CanonicalWebIndicatorModel(Base):
    """
    Identité canonique d'une URL.

    L'identité repose uniquement sur :

        (
            canonicalization_version,
            value_hash,
        )

    Le hostname est indexé pour la lecture, mais ne participe
    jamais à la corrélation.
    """

    __tablename__ = "canonical_web_indicator"

    __table_args__ = (
        UniqueConstraint(
            "canonicalization_version",
            "value_hash",
            name=(
                "canonical_web_indicator_"
                "version_value_hash"
            ),
        ),
        CheckConstraint(
            "indicator_type = 'url'",
            name="indicator_type_url",
        ),
        CheckConstraint(
            "canonicalization_version > 0",
            name=(
                "canonicalization_version_positive"
            ),
        ),
        CheckConstraint(
            "value_hash ~ '^[a-f0-9]{64}$'",
            name="value_hash_sha256",
        ),
        CheckConstraint(
            "char_length(canonical_value) "
            "BETWEEN 1 AND 4096",
            name="canonical_value_length_valid",
        ),
        CheckConstraint(
            "char_length(hostname) "
            "BETWEEN 1 AND 253",
            name="hostname_length_valid",
        ),
        CheckConstraint(
            "updated_at >= created_at",
            name="timestamps_order",
        ),
        Index(
            "ix_canonical_web_indicator_hostname",
            "hostname",
        ),
        Index(
            "ix_canonical_web_indicator_updated_at",
            "updated_at",
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

    indicator_type: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        default="url",
        server_default=text(
            "'url'"
        ),
    )

    canonical_value: Mapped[str] = mapped_column(
        Text,
        nullable=False,
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
            default=1,
            server_default=text(
                "1"
            ),
        )
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


class CanonicalWebIndicatorObservationModel(
    Base
):
    """
    Observation source reliée à une URL canonique.

    L'identité logique d'une observation est :

        (
            source,
            source_record_key,
        )

    Une observation ne peut jamais être déplacée silencieusement
    vers une autre URL canonique.
    """

    __tablename__ = (
        "canonical_web_indicator_observation"
    )

    __table_args__ = (
        UniqueConstraint(
            "source",
            "source_record_key",
            name=(
                "canonical_web_observation_"
                "source_record"
            ),
        ),
        CheckConstraint(
            "source ~ '^[a-z][a-z0-9_]*$'",
            name="source_format_valid",
        ),
        CheckConstraint(
            "btrim(source_record_key) <> ''",
            name="source_record_key_not_empty",
        ),
        CheckConstraint(
            "source_status IS NULL "
            "OR source_status "
            "~ '^[a-z][a-z0-9_]*$'",
            name="source_status_format_valid",
        ),
        CheckConstraint(
            "char_length(normalizer_version) "
            "BETWEEN 1 AND 30",
            name="normalizer_version_length_valid",
        ),
        CheckConstraint(
            "last_observed_at >= observed_at",
            name="observation_dates_order",
        ),
        CheckConstraint(
            "jsonb_typeof(labels) = 'array' "
            "AND jsonb_array_length(labels) <= 20",
            name="labels_array_bounded",
        ),
        Index(
            "ix_canonical_web_observation_"
            "indicator_id",
            "indicator_id",
        ),
        Index(
            "ix_canonical_web_observation_"
            "last_observed_at",
            "last_observed_at",
        ),
        Index(
            "ix_canonical_web_observation_"
            "normalized_record_id",
            "normalized_record_id",
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

    indicator_id: Mapped[
        uuid.UUID
    ] = mapped_column(
        UUID(
            as_uuid=True,
        ),
        ForeignKey(
            "canonical."
            "canonical_web_indicator.id",
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

    normalized_record_id: Mapped[
        uuid.UUID
    ] = mapped_column(
        UUID(
            as_uuid=True,
        ),
        nullable=False,
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

    normalizer_version: Mapped[str] = (
        mapped_column(
            String(30),
            nullable=False,
        )
    )

    source_status: Mapped[
        str | None
    ] = mapped_column(
        String(64),
        nullable=True,
    )

    is_active: Mapped[
        bool | None
    ] = mapped_column(
        Boolean,
        nullable=True,
    )

    labels: Mapped[
        list[str]
    ] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
        server_default=text(
            "'[]'::jsonb"
        ),
    )