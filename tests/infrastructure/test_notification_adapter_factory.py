from __future__ import annotations

import pytest

from infrastructure.notifications.disabled_notification_adapter import (
    DisabledNotificationAdapter,
)
from infrastructure.notifications.fake_notification_adapter import (
    FakeNotificationAdapter,
)
from infrastructure.notifications.gmail_notification_adapter import (
    GmailNotificationAdapter,
)
from infrastructure.notifications.notification_adapter_factory import (
    load_notification_port,
)


_REQUIRED_GMAIL_VALUES = {
    "TIP_GMAIL_CLIENT_ID":
        "test-client-id",
    "TIP_GMAIL_CLIENT_SECRET":
        "test-client-secret",
    "TIP_GMAIL_REFRESH_TOKEN":
        "test-refresh-token",
    "TIP_GMAIL_SENDER_EMAIL":
        "security@example.test",
}


def _configure_gmail_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for (
        name,
        value,
    ) in (
        _REQUIRED_GMAIL_VALUES
        .items()
    ):
        monkeypatch.setenv(
            name,
            value,
        )


def test_defaults_to_disabled_backend(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv(
        "TIP_NOTIFICATION_BACKEND",
        raising=False,
    )

    adapter = (
        load_notification_port()
    )

    assert isinstance(
        adapter,
        DisabledNotificationAdapter,
    )


def test_explicit_disabled_backend(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        "TIP_NOTIFICATION_BACKEND",
        "disabled",
    )

    adapter = (
        load_notification_port()
    )

    assert isinstance(
        adapter,
        DisabledNotificationAdapter,
    )


def test_gmail_backend_uses_existing_gmail_adapter(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        "TIP_NOTIFICATION_BACKEND",
        "gmail",
    )

    _configure_gmail_environment(
        monkeypatch
    )

    expected_adapter = (
        FakeNotificationAdapter()
    )

    monkeypatch.setattr(
        GmailNotificationAdapter,
        "from_env",
        classmethod(
            lambda cls: (
                expected_adapter
            )
        ),
    )

    adapter = (
        load_notification_port()
    )

    assert (
        adapter
        is expected_adapter
    )


def test_gmail_backend_requires_credentials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        "TIP_NOTIFICATION_BACKEND",
        "gmail",
    )

    for name in (
        _REQUIRED_GMAIL_VALUES
    ):
        monkeypatch.delenv(
            name,
            raising=False,
        )

    with pytest.raises(
        RuntimeError,
        match=(
            "TIP_GMAIL_CLIENT_ID "
            "must be configured"
        ),
    ):
        load_notification_port()


def test_gmail_backend_rejects_change_me(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        "TIP_NOTIFICATION_BACKEND",
        "gmail",
    )

    _configure_gmail_environment(
        monkeypatch
    )

    monkeypatch.setenv(
        "TIP_GMAIL_REFRESH_TOKEN",
        "CHANGE_ME",
    )

    with pytest.raises(
        RuntimeError,
        match=(
            "TIP_GMAIL_REFRESH_TOKEN "
            "must be configured"
        ),
    ):
        load_notification_port()


def test_unknown_backend_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        "TIP_NOTIFICATION_BACKEND",
        "smtp",
    )

    with pytest.raises(
        RuntimeError,
        match=(
            "TIP_NOTIFICATION_BACKEND "
            "must be one of"
        ),
    ):
        load_notification_port()


def test_empty_backend_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        "TIP_NOTIFICATION_BACKEND",
        "   ",
    )

    with pytest.raises(
        RuntimeError,
        match=(
            "TIP_NOTIFICATION_BACKEND "
            "must not be empty"
        ),
    ):
        load_notification_port()