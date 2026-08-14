from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

import pytest

from domain.alert import Alert
from domain.software_component import (
    SoftwareComponent,
)
from domain.user_account import UserAccount
from domain.vulnerability_exposure import (
    VulnerabilityExposure,
)


NOW = datetime(
    2026,
    8,
    14,
    14,
    30,
    tzinfo=timezone.utc,
)


def test_user_account_rejects_unknown_role() -> None:
    with pytest.raises(
        ValueError,
        match="role must be one of",
    ):
        UserAccount(
            id=uuid4(),
            organization_id=uuid4(),
            email="security@example.com",
            display_name="Security",
            role="admin",
            is_active=True,
            created_at=NOW,
        )


def test_application_requires_external_id() -> None:
    with pytest.raises(
        ValueError,
        match="external_id is required",
    ):
        SoftwareComponent(
            id=uuid4(),
            machine_id=uuid4(),
            component_type="application",
            name="7-Zip",
            normalized_name="7-zip",
            version="24.09",
            vendor="Igor Pavlov",
            normalized_vendor="igor pavlov",
            ecosystem=None,
            external_id=None,
            scope=None,
            detected_by=(
                "windows_registry_uninstall"
            ),
            created_at=NOW,
            updated_at=NOW,
        )


def test_exposure_keeps_potential_separate_from_priority() -> None:
    exposure = VulnerabilityExposure(
        id=uuid4(),
        software_component_id=uuid4(),
        canonical_vulnerability_id=uuid4(),
        applicability_status="potential",
        match_rule="cisa_kev_product_match_v1",
        match_version=None,
        severity="critical",
        priority=None,
        is_kev=True,
        first_detected_at=NOW,
        last_evaluated_at=NOW,
    )

    assert (
        exposure.applicability_status
        == "potential"
    )
    assert exposure.severity == "CRITICAL"
    assert exposure.priority is None


def test_pending_alert_must_not_have_sent_at() -> None:
    with pytest.raises(
        ValueError,
        match="sent_at is only allowed",
    ):
        Alert(
            id=uuid4(),
            organization_id=uuid4(),
            machine_id=uuid4(),
            vulnerability_exposure_id=uuid4(),
            canonical_vulnerability_id=uuid4(),
            alert_type=(
                "new_confirmed_critical_exposure"
            ),
            recipient_user_id=uuid4(),
            status="pending",
            deduplication_key=(
                "alert:v1:test"
            ),
            created_at=NOW,
            sent_at=NOW,
        )