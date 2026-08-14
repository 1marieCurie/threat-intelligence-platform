from __future__ import annotations

from uuid import UUID

import pytest

from application.models.machine_inventory_v1 import (
    InventoryApplicationComponentV1,
    InventoryPackageComponentV1,
    InventoryValidationError,
    MachineInventoryV1,
)


def _base_payload() -> dict[str, object]:
    return {
        "schema_version": "inventory/v1",
        "inventory_id": (
            "bda8c103-6334-4cf3-8d84-6582975d78f7"
        ),
        "collected_at": "2026-08-14T14:30:00Z",
        "agent": {
            "name": "tip-windows-agent",
            "version": "0.1.0",
        },
        "machine": {
            "machine_uid": (
                "443258c4-5a37-4221-b96c-3759395068d6"
            ),
            "hostname": "DESKTOP-01",
            "os_name": "Windows 11 Pro",
            "os_version": "10.0.26100",
            "architecture": "x86_64",
        },
        "components": [
            {
                "component_type": "application",
                "name": (
                    "7-Zip 24.09 (x64 edition)"
                ),
                "version": "24.09",
                "vendor": "Igor Pavlov",
                "external_id": (
                    "HKLM64\\SOFTWARE\\Microsoft\\Windows\\"
                    "CurrentVersion\\Uninstall\\7-Zip"
                ),
                "detected_by": (
                    "windows_registry_uninstall"
                ),
            },
            {
                "component_type": "package",
                "ecosystem": "pypi",
                "package_name": "requests",
                "version": "2.32.3",
                "scope": "global",
                "detected_by": "pip_global",
            },
        ],
    }


def test_parses_valid_inventory_v1() -> None:
    inventory = MachineInventoryV1.from_mapping(
        _base_payload()
    )

    assert inventory.schema_version == (
        "inventory/v1"
    )
    assert inventory.inventory_id == UUID(
        "bda8c103-6334-4cf3-8d84-6582975d78f7"
    )
    assert len(inventory.components) == 2

    assert isinstance(
        inventory.components[0],
        InventoryApplicationComponentV1,
    )
    assert isinstance(
        inventory.components[1],
        InventoryPackageComponentV1,
    )


def test_rejects_organization_id_from_scanner() -> None:
    payload = _base_payload()

    payload["organization_id"] = (
        "41dc2af1-c5c5-4688-a449-d6e2a1af2dc2"
    )

    with pytest.raises(
        InventoryValidationError,
        match="unsupported fields: organization_id",
    ):
        MachineInventoryV1.from_mapping(
            payload
        )


def test_rejects_threat_intelligence_fields() -> None:
    payload = _base_payload()

    component = payload["components"][0]  # type: ignore[index]
    component["cve"] = "CVE-2026-1234"  # type: ignore[index]

    with pytest.raises(
        InventoryValidationError,
        match="unsupported fields: cve",
    ):
        MachineInventoryV1.from_mapping(
            payload
        )


def test_rejects_naive_collected_at() -> None:
    payload = _base_payload()

    payload["collected_at"] = (
        "2026-08-14T14:30:00"
    )

    with pytest.raises(
        InventoryValidationError,
        match="must include a timezone",
    ):
        MachineInventoryV1.from_mapping(
            payload
        )


def test_package_detector_must_match_ecosystem() -> None:
    payload = _base_payload()

    package = payload["components"][1]  # type: ignore[index]
    package["detected_by"] = "npm_global"  # type: ignore[index]

    with pytest.raises(
        InventoryValidationError,
        match="must be 'pip_global'",
    ):
        MachineInventoryV1.from_mapping(
            payload
        )