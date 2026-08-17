from __future__ import annotations

from uuid import uuid4

import pytest

from application.ports.outbound.notification_port import (
    AlertNotification,
    NotificationDeliveryError,
)
from infrastructure.notifications.fake_notification_adapter import (
    FakeNotificationAdapter,
)


def _notification(
    *,
    alert_id=None,
) -> AlertNotification:
    return AlertNotification(
        alert_id=(
            alert_id
            or uuid4()
        ),
        organization_id=uuid4(),
        machine_id=uuid4(),
        vulnerability_exposure_id=uuid4(),
        canonical_vulnerability_id=uuid4(),
        alert_type=(
            "priority_transition_to_critical"
        ),
        recipient_user_id=uuid4(),
        recipient_email=(
            "security@example.test"
        ),
        recipient_display_name=(
            "Security Responsible"
        ),
    )


def test_fake_notification_adapter_records_successful_delivery(
) -> None:
    adapter = (
        FakeNotificationAdapter()
    )

    notification = _notification()

    adapter.send(
        notification
    )

    assert (
        adapter.attempted_notifications
        == [
            notification
        ]
    )

    assert (
        adapter.sent_notifications
        == [
            notification
        ]
    )


def test_fake_notification_adapter_can_fail_deterministically(
) -> None:
    alert_id = uuid4()

    adapter = (
        FakeNotificationAdapter(
            fail_for_alert_ids=frozenset(
                {
                    alert_id,
                }
            )
        )
    )

    notification = _notification(
        alert_id=alert_id
    )

    with pytest.raises(
        NotificationDeliveryError,
        match="Simulated",
    ):
        adapter.send(
            notification
        )

    assert (
        adapter.attempted_notifications
        == [
            notification
        ]
    )

    assert (
        adapter.sent_notifications
        == []
    )


def test_fake_adapter_rejects_invalid_notification(
) -> None:
    adapter = (
        FakeNotificationAdapter()
    )

    with pytest.raises(
        TypeError,
        match="AlertNotification",
    ):
        adapter.send(
            object()  # type: ignore[arg-type]
        )