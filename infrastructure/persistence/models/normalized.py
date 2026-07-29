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
    Float,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import (
    ARRAY,
    UUID,
    JSONB,
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
    
class GitHubAdvisoryVulnerabilityModel(Base):
    __tablename__ = (
        "github_advisory_vulnerability"
    )

    __table_args__ = (
        UniqueConstraint(
            "raw_payload_id",
            name="github_advisory_raw_payload",
        ),
        CheckConstraint(
            "cvss_score IS NULL OR "
            "(cvss_score >= 0 AND cvss_score <= 10)",
            name="cvss_score_range",
        ),
        CheckConstraint(
            "epss_score IS NULL OR "
            "(epss_score >= 0 AND epss_score <= 1)",
            name="epss_score_range",
        ),
        CheckConstraint(
            "epss_percentile IS NULL OR "
            "(epss_percentile >= 0 "
            "AND epss_percentile <= 1)",
            name="epss_percentile_range",
        ),
        Index(
            "ix_github_advisory_"
            "vulnerability_ghsa_updated",
            "ghsa_id",
            "updated_at",
        ),
        Index(
            "ix_github_advisory_"
            "vulnerability_cve_id",
            "cve_id",
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

    raw_payload_id: Mapped[uuid.UUID] = (
        mapped_column(
            UUID(as_uuid=True),
            ForeignKey(
                "raw.source_payload.id",
                ondelete="RESTRICT",
            ),
            nullable=False,
        )
    )

    ghsa_id: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
    )

    cve_id: Mapped[str | None] = mapped_column(
        String(32),
        nullable=True,
    )

    advisory_type: Mapped[
        str | None
    ] = mapped_column(
        String(50),
        nullable=True,
    )

    severity: Mapped[
        str | None
    ] = mapped_column(
        String(20),
        nullable=True,
    )

    summary: Mapped[
        str | None
    ] = mapped_column(
        Text,
        nullable=True,
    )

    description: Mapped[
        str | None
    ] = mapped_column(
        Text,
        nullable=True,
    )

    published_at: Mapped[
        datetime | None
    ] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    updated_at: Mapped[
        datetime | None
    ] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    reviewed_at: Mapped[
        datetime | None
    ] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    withdrawn_at: Mapped[
        datetime | None
    ] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    cvss_score: Mapped[
        float | None
    ] = mapped_column(
        Float,
        nullable=True,
    )

    cvss_metrics: Mapped[
        list[dict[str, object]]
    ] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
        server_default=text(
            "'[]'::jsonb"
        ),
    )

    epss_score: Mapped[
        float | None
    ] = mapped_column(
        Float,
        nullable=True,
    )

    epss_percentile: Mapped[
        float | None
    ] = mapped_column(
        Float,
        nullable=True,
    )

    affected_packages: Mapped[
        list[dict[str, object]]
    ] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
        server_default=text(
            "'[]'::jsonb"
        ),
    )

    cwe_ids: Mapped[
        list[str]
    ] = mapped_column(
        ARRAY(
            String(32),
        ),
        nullable=False,
        default=list,
        server_default=text(
            "'{}'::character varying[]"
        ),
    )

    references: Mapped[
        list[str]
    ] = mapped_column(
        ARRAY(
            Text(),
        ),
        nullable=False,
        default=list,
        server_default=text(
            "'{}'::text[]"
        ),
    )

    api_url: Mapped[
        str | None
    ] = mapped_column(
        Text,
        nullable=True,
    )

    html_url: Mapped[
        str | None
    ] = mapped_column(
        Text,
        nullable=True,
    )

    repository_advisory_url: Mapped[
        str | None
    ] = mapped_column(
        Text,
        nullable=True,
    )

    source_code_locations: Mapped[
        list[str]
    ] = mapped_column(
        ARRAY(
            Text(),
        ),
        nullable=False,
        default=list,
        server_default=text(
            "'{}'::text[]"
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
    
class CWEWeaknessModel(Base):
    """
    Entrée officielle du catalogue MITRE CWE.

    Une seule ligne est conservée par identifiant canonique.
    Les payloads MITRE bruts ne sont volontairement pas persistés.
    """

    __tablename__ = "cwe_weakness"

    __table_args__ = (
        CheckConstraint(
            "cwe_id ~ '^CWE-[1-9][0-9]*$'",
            name="cwe_id_valid",
        ),
        {
            "schema": "normalized",
        },
    )

    cwe_id: Mapped[str] = mapped_column(
        String(32),
        primary_key=True,
    )

    name: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    description: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    abstraction: Mapped[str | None] = mapped_column(
        String(50),
        nullable=True,
    )

    structure: Mapped[str | None] = mapped_column(
        String(50),
        nullable=True,
    )

    status: Mapped[str | None] = mapped_column(
        String(50),
        nullable=True,
    )

    extended_description: Mapped[
        str | None
    ] = mapped_column(
        Text,
        nullable=True,
    )

    likelihood_of_exploit: Mapped[
        str | None
    ] = mapped_column(
        String(50),
        nullable=True,
    )

    mapping_usage: Mapped[
        str | None
    ] = mapped_column(
        Text,
        nullable=True,
    )

    mapping_rationale: Mapped[
        str | None
    ] = mapped_column(
        Text,
        nullable=True,
    )

    relationships: Mapped[
        list[dict[str, object]]
    ] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
        server_default=text(
            "'[]'::jsonb"
        ),
    )

    consequences: Mapped[
        list[dict[str, object]]
    ] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
        server_default=text(
            "'[]'::jsonb"
        ),
    )

    mitigations: Mapped[
        list[dict[str, object]]
    ] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
        server_default=text(
            "'[]'::jsonb"
        ),
    )

    detection_methods: Mapped[
        list[dict[str, object]]
    ] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
        server_default=text(
            "'[]'::jsonb"
        ),
    )

    applicable_platforms: Mapped[
        list[dict[str, object]]
    ] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
        server_default=text(
            "'[]'::jsonb"
        ),
    )

    modes_of_introduction: Mapped[
        list[dict[str, object]]
    ] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
        server_default=text(
            "'[]'::jsonb"
        ),
    )

    alternate_terms: Mapped[
        list[str]
    ] = mapped_column(
        ARRAY(
            Text(),
        ),
        nullable=False,
        default=list,
        server_default=text(
            "'{}'::text[]"
        ),
    )

    related_capec_ids: Mapped[
        list[str]
    ] = mapped_column(
        ARRAY(
            String(32),
        ),
        nullable=False,
        default=list,
        server_default=text(
            "'{}'::character varying[]"
        ),
    )

    catalog_version: Mapped[
        str | None
    ] = mapped_column(
        String(50),
        nullable=True,
    )

    catalog_date: Mapped[
        str | None
    ] = mapped_column(
        String(32),
        nullable=True,
    )

    synchronized_at: Mapped[
        datetime
    ] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )