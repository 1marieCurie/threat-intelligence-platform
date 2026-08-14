from __future__ import annotations

from infrastructure.persistence.models.assets import (
    AlertModel,
    MachineInventoryStateModel,
    MachineModel,
    OrganizationModel,
    SoftwareComponentModel,
    UserAccountModel,
    VulnerabilityExposureModel,
)


def test_asset_core_tables_use_threat_intel_schema() -> None:
    models = (
        OrganizationModel,
        UserAccountModel,
        MachineModel,
        MachineInventoryStateModel,
        SoftwareComponentModel,
        VulnerabilityExposureModel,
        AlertModel,
    )

    assert all(
        model.__table__.schema == "threat_intel"
        for model in models
    )


def test_inventory_state_is_one_to_one_with_machine() -> None:
    table = MachineInventoryStateModel.__table__

    assert table.c.machine_id.primary_key is True
    assert table.c.inventory_id.unique is not True


def test_normalized_component_fields_can_be_deferred() -> None:
    table = SoftwareComponentModel.__table__

    assert table.c.normalized_name.nullable is True
    assert table.c.normalized_vendor.nullable is True


def test_exposure_reuses_canonical_vulnerability() -> None:
    foreign_keys = {
        foreign_key.target_fullname
        for foreign_key
        in VulnerabilityExposureModel
        .__table__
        .c
        .canonical_vulnerability_id
        .foreign_keys
    }

    assert foreign_keys == {
        "canonical.canonical_vulnerability.id"
    }


def test_alert_exposure_reference_is_nullable() -> None:
    column = (
        AlertModel
        .__table__
        .c
        .vulnerability_exposure_id
    )

    assert column.nullable is True

    foreign_key = next(iter(column.foreign_keys))

    assert foreign_key.ondelete == "SET NULL"


def test_alert_has_tenant_aware_foreign_keys() -> None:
    constraint_names = {
        constraint.name
        for constraint
        in AlertModel.__table__.foreign_key_constraints # type: ignore
    }

    assert "fk_alert_organization_machine" in constraint_names
    assert "fk_alert_organization_recipient" in constraint_names


def test_software_component_has_distinct_identity_indexes() -> None:
    index_names = {
        index.name
        for index in SoftwareComponentModel.__table__.indexes # type: ignore
    }

    assert (
        "uq_software_component_application_identity"
        in index_names
    )
    assert (
        "uq_software_component_package_identity"
        in index_names
    )