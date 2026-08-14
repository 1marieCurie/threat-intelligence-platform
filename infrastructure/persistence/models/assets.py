from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    String,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from infrastructure.persistence.models.base import Base


SCHEMA = "threat_intel"


class OrganizationModel(Base):
    __tablename__ = "organization"

    __table_args__ = (
        CheckConstraint(
            "char_length(btrim(name)) > 0",
            name="name_not_blank",
        ),
        {
            "schema": SCHEMA,
        },
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    is_active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        server_default=text("true"),
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )


class UserAccountModel(Base):
    __tablename__ = "user_account"

    __table_args__ = (
        UniqueConstraint(
            "organization_id",
            "id",
            name="user_account_organization_id_id",
        ),
        CheckConstraint(
            "role IN ('security_responsible', 'staff')",
            name="role_valid",
        ),
        CheckConstraint(
            (
                "email = lower(btrim(email)) "
                "AND position('@' in email) > 1"
            ),
            name="email_normalized",
        ),
        Index(
            "ix_user_account_organization_id",
            "organization_id",
        ),
        {
            "schema": SCHEMA,
        },
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey(
            f"{SCHEMA}.organization.id",
            ondelete="RESTRICT",
        ),
        nullable=False,
    )

    email: Mapped[str] = mapped_column(
        String(320),
        nullable=False,
    )

    display_name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    role: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
    )

    is_active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        server_default=text("true"),
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )


Index(
    "uq_user_account_organization_email_lower",
    UserAccountModel.organization_id,
    func.lower(UserAccountModel.email),
    unique=True,
)


class MachineModel(Base):
    __tablename__ = "machine"

    __table_args__ = (
        UniqueConstraint(
            "organization_id",
            "machine_uid",
            name="machine_organization_uid",
        ),
        UniqueConstraint(
            "organization_id",
            "id",
            name="machine_organization_id_id",
        ),
        CheckConstraint(
            "char_length(btrim(hostname)) > 0",
            name="hostname_not_blank",
        ),
        CheckConstraint(
            "char_length(btrim(os_name)) > 0",
            name="os_name_not_blank",
        ),
        CheckConstraint(
            "char_length(btrim(os_version)) > 0",
            name="os_version_not_blank",
        ),
        CheckConstraint(
            "char_length(btrim(architecture)) > 0",
            name="architecture_not_blank",
        ),
        CheckConstraint(
            "updated_at >= created_at",
            name="timestamps_order",
        ),
        Index(
            "ix_machine_organization_id",
            "organization_id",
        ),
        Index(
            "ix_machine_last_inventory_at",
            "last_inventory_at",
        ),
        {
            "schema": SCHEMA,
        },
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey(
            f"{SCHEMA}.organization.id",
            ondelete="RESTRICT",
        ),
        nullable=False,
    )

    machine_uid: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
    )

    hostname: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    os_name: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
    )

    os_version: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
    )

    architecture: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
    )

    last_inventory_at: Mapped[
        datetime | None
    ] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )


class MachineInventoryStateModel(Base):
    __tablename__ = "machine_inventory_state"

    __table_args__ = (
        CheckConstraint(
            "schema_version = 'inventory/v1'",
            name="schema_version_valid",
        ),
        CheckConstraint(
            "component_count >= 0",
            name="component_count_non_negative",
        ),
        {
            "schema": SCHEMA,
        },
    )

    machine_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey(
            f"{SCHEMA}.machine.id",
            ondelete="CASCADE",
        ),
        primary_key=True,
    )

    inventory_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
    )

    schema_version: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
    )

    collected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )

    imported_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )

    component_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )


class SoftwareComponentModel(Base):
    __tablename__ = "software_component"

    __table_args__ = (
        CheckConstraint(
            "component_type IN ('application', 'package')",
            name="component_type_valid",
        ),
        CheckConstraint(
            "updated_at >= created_at",
            name="timestamps_order",
        ),
        CheckConstraint(
            (
                "vendor IS NOT NULL "
                "OR normalized_vendor IS NULL"
            ),
            name="normalized_vendor_requires_vendor",
        ),
        CheckConstraint(
            (
                "(component_type = 'application' "
                "AND ecosystem IS NULL "
                "AND scope IS NULL "
                "AND external_id IS NOT NULL) "
                "OR "
                "(component_type = 'package' "
                "AND ecosystem IN ('pypi', 'npm') "
                "AND version IS NOT NULL "
                "AND scope = 'global' "
                "AND external_id IS NULL)"
            ),
            name="type_fields_consistent",
        ),
        Index(
            "ix_software_component_machine_id",
            "machine_id",
        ),
        Index(
            "ix_software_component_normalized_name",
            "normalized_name",
        ),
        Index(
            "ix_software_component_ecosystem_normalized_name",
            "ecosystem",
            "normalized_name",
        ),
        Index(
            "uq_software_component_application_identity",
            "machine_id",
            "detected_by",
            "external_id",
            unique=True,
            postgresql_where=text(
                "component_type = 'application'"
            ),
        ),
        Index(
            "uq_software_component_package_identity",
            "machine_id",
            "ecosystem",
            "name",
            "scope",
            "detected_by",
            unique=True,
            postgresql_where=text(
                "component_type = 'package'"
            ),
        ),
        {
            "schema": SCHEMA,
        },
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    machine_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey(
            f"{SCHEMA}.machine.id",
            ondelete="CASCADE",
        ),
        nullable=False,
    )

    component_type: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
    )

    name: Mapped[str] = mapped_column(
        String(512),
        nullable=False,
    )

    normalized_name: Mapped[
        str | None
    ] = mapped_column(
        String(512),
        nullable=True,
    )

    version: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    vendor: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    normalized_vendor: Mapped[
        str | None
    ] = mapped_column(
        String(255),
        nullable=True,
    )

    ecosystem: Mapped[str | None] = mapped_column(
        String(32),
        nullable=True,
    )

    external_id: Mapped[str | None] = mapped_column(
        String(1024),
        nullable=True,
    )

    scope: Mapped[str | None] = mapped_column(
        String(32),
        nullable=True,
    )

    detected_by: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )


class VulnerabilityExposureModel(Base):
    __tablename__ = "vulnerability_exposure"

    __table_args__ = (
        UniqueConstraint(
            "software_component_id",
            "canonical_vulnerability_id",
            name=(
                "vulnerability_exposure_"
                "component_vulnerability"
            ),
        ),
        CheckConstraint(
            (
                "applicability_status "
                "IN ('confirmed', 'potential')"
            ),
            name="applicability_status_valid",
        ),
        CheckConstraint(
            (
                "severity IS NULL OR severity IN "
                "('NONE', 'LOW', 'MEDIUM', "
                "'HIGH', 'CRITICAL')"
            ),
            name="severity_valid",
        ),
        CheckConstraint(
            (
                "priority IS NULL OR priority IN "
                "('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')"
            ),
            name="priority_valid",
        ),
        CheckConstraint(
            "last_evaluated_at >= first_detected_at",
            name="timestamps_order",
        ),
        Index(
            (
                "ix_vulnerability_exposure_"
                "canonical_vulnerability_id"
            ),
            "canonical_vulnerability_id",
        ),
        Index(
            "ix_vulnerability_exposure_priority",
            "priority",
        ),
        {
            "schema": SCHEMA,
        },
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    software_component_id: Mapped[
        uuid.UUID
    ] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey(
            f"{SCHEMA}.software_component.id",
            ondelete="CASCADE",
        ),
        nullable=False,
    )

    canonical_vulnerability_id: Mapped[
        uuid.UUID
    ] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey(
            "canonical.canonical_vulnerability.id",
            ondelete="RESTRICT",
        ),
        nullable=False,
    )

    applicability_status: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
    )

    match_rule: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
    )

    match_version: Mapped[
        str | None
    ] = mapped_column(
        String(255),
        nullable=True,
    )

    severity: Mapped[str | None] = mapped_column(
        String(16),
        nullable=True,
    )

    priority: Mapped[str | None] = mapped_column(
        String(16),
        nullable=True,
    )

    is_kev: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default=text("false"),
    )

    first_detected_at: Mapped[
        datetime
    ] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )

    last_evaluated_at: Mapped[
        datetime
    ] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )


class AlertModel(Base):
    __tablename__ = "alert"

    __table_args__ = (
        UniqueConstraint(
            "organization_id",
            "deduplication_key",
            name="alert_organization_deduplication_key",
        ),
        ForeignKeyConstraint(
            [
                "organization_id",
                "machine_id",
            ],
            [
                f"{SCHEMA}.machine.organization_id",
                f"{SCHEMA}.machine.id",
            ],
            name="fk_alert_organization_machine",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            [
                "organization_id",
                "recipient_user_id",
            ],
            [
                (
                    f"{SCHEMA}."
                    "user_account.organization_id"
                ),
                f"{SCHEMA}.user_account.id",
            ],
            name="fk_alert_organization_recipient",
            ondelete="RESTRICT",
        ),
        CheckConstraint(
            (
                "alert_type IN ("
                "'new_confirmed_critical_exposure', "
                "'confirmed_exposure_entered_kev', "
                "'priority_transition_to_critical'"
                ")"
            ),
            name="alert_type_valid",
        ),
        CheckConstraint(
            "status IN ('pending', 'sent', 'failed')",
            name="status_valid",
        ),
        CheckConstraint(
            (
                "(status = 'sent' "
                "AND sent_at IS NOT NULL) "
                "OR "
                "(status IN ('pending', 'failed') "
                "AND sent_at IS NULL)"
            ),
            name="sent_at_consistent",
        ),
        CheckConstraint(
            (
                "sent_at IS NULL "
                "OR sent_at >= created_at"
            ),
            name="timestamps_order",
        ),
        Index(
            "ix_alert_organization_status",
            "organization_id",
            "status",
        ),
        Index(
            "ix_alert_machine_id",
            "machine_id",
        ),
        Index(
            "ix_alert_canonical_vulnerability_id",
            "canonical_vulnerability_id",
        ),
        {
            "schema": SCHEMA,
        },
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    organization_id: Mapped[
        uuid.UUID
    ] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey(
            f"{SCHEMA}.organization.id",
            ondelete="RESTRICT",
        ),
        nullable=False,
    )

    machine_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
    )

    vulnerability_exposure_id: Mapped[
        uuid.UUID | None
    ] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey(
            f"{SCHEMA}.vulnerability_exposure.id",
            ondelete="SET NULL",
        ),
        nullable=True,
    )

    canonical_vulnerability_id: Mapped[
        uuid.UUID
    ] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey(
            "canonical.canonical_vulnerability.id",
            ondelete="RESTRICT",
        ),
        nullable=False,
    )

    alert_type: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )

    recipient_user_id: Mapped[
        uuid.UUID
    ] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
    )

    status: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
    )

    deduplication_key: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )

    sent_at: Mapped[
        datetime | None
    ] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )