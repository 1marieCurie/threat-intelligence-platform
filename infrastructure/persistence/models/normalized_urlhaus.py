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


class URLhausURLModel(Base):
    """
    Représentation normalisée d'une observation URLhaus.

    Un même urlhaus_id peut avoir plusieurs versions brutes dans
    le temps. L'unicité porte donc uniquement sur raw_payload_id.
    """

    __tablename__ = "urlhaus_url"

    __table_args__ = (
        UniqueConstraint(
            "raw_payload_id",
            name="urlhaus_url_raw_payload",
        ),
        CheckConstraint(
            "urlhaus_id > 0",
            name="urlhaus_id_positive",
        ),
        CheckConstraint(
            "char_length(malicious_url) "
            "BETWEEN 1 AND 4096",
            name="malicious_url_length_valid",
        ),
        CheckConstraint(
            "char_length(hostname) "
            "BETWEEN 1 AND 253",
            name="hostname_length_valid",
        ),
        CheckConstraint(
            "urlhaus_reference IS NULL "
            "OR char_length(urlhaus_reference) "
            "BETWEEN 1 AND 4096",
            name="urlhaus_reference_length_valid",
        ),
        CheckConstraint(
            "jsonb_typeof(tags) = 'array' "
            "AND jsonb_array_length(tags) <= 100",
            name="tags_array_bounded",
        ),
        CheckConstraint(
            "jsonb_typeof(blacklists) = 'array' "
            "AND jsonb_array_length(blacklists) <= 50",
            name="blacklists_array_bounded",
        ),
        CheckConstraint(
            "char_length(normalizer_version) "
            "BETWEEN 1 AND 30",
            name="normalizer_version_length_valid",
        ),
        Index(
            "ix_urlhaus_url_urlhaus_id",
            "urlhaus_id",
        ),
        Index(
            "ix_urlhaus_url_hostname",
            "hostname",
        ),
        Index(
            "ix_urlhaus_url_status",
            "url_status",
        ),
        Index(
            "ix_urlhaus_url_date_added",
            "date_added",
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

    raw_payload_id: Mapped[
        uuid.UUID
    ] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey(
            "raw.source_payload.id",
            ondelete="RESTRICT",
        ),
        nullable=False,
    )

    urlhaus_id: Mapped[int] = mapped_column(
        BigInteger,
        nullable=False,
    )

    malicious_url: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    hostname: Mapped[str] = mapped_column(
        String(253),
        nullable=False,
    )

    urlhaus_reference: Mapped[
        str | None
    ] = mapped_column(
        Text,
        nullable=True,
    )

    url_status: Mapped[
        str | None
    ] = mapped_column(
        String(32),
        nullable=True,
    )

    date_added: Mapped[
        datetime | None
    ] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    threat_type: Mapped[
        str | None
    ] = mapped_column(
        String(100),
        nullable=True,
    )

    reporter: Mapped[
        str | None
    ] = mapped_column(
        String(255),
        nullable=True,
    )

    larted: Mapped[
        bool | None
    ] = mapped_column(
        Boolean,
        nullable=True,
    )

    tags: Mapped[
        list[str]
    ] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
        server_default=text(
            "'[]'::jsonb"
        ),
    )

    blacklists: Mapped[
        list[dict[str, str]]
    ] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
        server_default=text(
            "'[]'::jsonb"
        ),
    )

    normalizer_version: Mapped[
        str
    ] = mapped_column(
        String(30),
        nullable=False,
    )

    normalized_at: Mapped[
        datetime
    ] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )