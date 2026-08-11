from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import (
    UUID,
)
from sqlalchemy.orm import (
    Mapped,
    mapped_column,
)

from infrastructure.persistence.models.base import (
    Base,
)


class HTTPArchivePageModel(Base):
    """
    Représentation normalisée d'une page HTTP Archive.

    La canonical_value complète est conservée avant
    toute projection ML.

    Cette table ne porte volontairement aucun label
    benign : HTTP Archive reste une source, tandis que
    le label est une décision du pipeline ML.
    """

    __tablename__ = "http_archive_page"

    __table_args__ = (
        UniqueConstraint(
            "source_snapshot",
            "canonicalization_version",
            "value_hash",
            name="uq_http_archive_snapshot_url",
        ),
        CheckConstraint(
            "char_length(canonical_value) "
            "BETWEEN 1 AND 4096",
            name="canonical_value_valid",
        ),
        CheckConstraint(
            "value_hash ~ '^[a-f0-9]{64}$'",
            name="value_hash_valid",
        ),
        CheckConstraint(
            "char_length(hostname) "
            "BETWEEN 1 AND 253",
            name="hostname_valid",
        ),
        CheckConstraint(
            "char_length(registered_domain) "
            "BETWEEN 1 AND 253",
            name="registered_domain_valid",
        ),
        CheckConstraint(
            "canonicalization_version > 0",
            name="canonicalization_version_positive",
        ),
        CheckConstraint(
            "source_rank > 0",
            name="source_rank_positive",
        ),
        CheckConstraint(
            "char_length(source_snapshot) "
            "BETWEEN 1 AND 100",
            name="source_snapshot_valid",
        ),
        Index(
            "ix_http_archive_snapshot_rank",
            "source_snapshot",
            "source_rank",
        ),
        Index(
            "ix_http_archive_registered_domain",
            "registered_domain",
        ),
        Index(
            "ix_http_archive_value_hash",
            "value_hash",
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

    registered_domain: Mapped[str] = mapped_column(
        String(253),
        nullable=False,
    )

    canonicalization_version: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )

    source_rank: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )

    source_snapshot: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    observed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )

    normalized_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )