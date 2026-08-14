from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

import pytest

from domain.software_component import (
    SoftwareComponent,
)


def test_raw_application_can_exist_before_normalization() -> None:
    now = datetime.now(timezone.utc)

    component = SoftwareComponent(
        id=uuid4(),
        machine_id=uuid4(),
        component_type="application",
        name="7-Zip 24.09",
        normalized_name=None,
        version="24.09",
        vendor="Igor Pavlov",
        normalized_vendor=None,
        ecosystem=None,
        external_id=(
            "HKLM64\\SOFTWARE\\Microsoft\\Windows\\"
            "CurrentVersion\\Uninstall\\7-Zip"
        ),
        scope=None,
        detected_by="windows_registry_uninstall",
        created_at=now,
        updated_at=now,
    )

    assert component.normalized_name is None
    assert component.normalized_vendor is None


def test_normalized_vendor_requires_raw_vendor() -> None:
    now = datetime.now(timezone.utc)

    with pytest.raises(
        ValueError,
        match="normalized_vendor requires vendor",
    ):
        SoftwareComponent(
            id=uuid4(),
            machine_id=uuid4(),
            component_type="application",
            name="Example",
            normalized_name="example",
            version="1.0",
            vendor=None,
            normalized_vendor="example vendor",
            ecosystem=None,
            external_id="registry-key",
            scope=None,
            detected_by="windows_registry_uninstall",
            created_at=now,
            updated_at=now,
        )