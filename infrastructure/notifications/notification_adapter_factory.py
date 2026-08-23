from __future__ import annotations

import os

from application.ports.outbound.notification_port import (
    NotificationPort,
)
from infrastructure.notifications.disabled_notification_adapter import (
    DisabledNotificationAdapter,
)
from infrastructure.notifications.gmail_notification_adapter import (
    GmailNotificationAdapter,
)


_REQUIRED_GMAIL_ENVIRONMENT = (
    "TIP_GMAIL_CLIENT_ID",
    "TIP_GMAIL_CLIENT_SECRET",
    "TIP_GMAIL_REFRESH_TOKEN",
    "TIP_GMAIL_SENDER_EMAIL",
)


def load_notification_port(
) -> NotificationPort:
    backend_raw = os.getenv(
        "TIP_NOTIFICATION_BACKEND"
    )

    if backend_raw is None:
        backend = "disabled"

    else:
        backend = (
            backend_raw
            .strip()
            .lower()
        )

        if not backend:
            raise RuntimeError(
                (
                    "TIP_NOTIFICATION_BACKEND "
                    "must not be empty"
                )
            )

    if backend == "disabled":
        return (
            DisabledNotificationAdapter()
        )

    if backend == "gmail":
        _validate_gmail_environment()

        return (
            GmailNotificationAdapter
            .from_env()
        )

    raise RuntimeError(
        (
            "TIP_NOTIFICATION_BACKEND "
            "must be one of: "
            "disabled, gmail"
        )
    )


def _validate_gmail_environment(
) -> None:
    for name in (
        _REQUIRED_GMAIL_ENVIRONMENT
    ):
        raw_value = os.getenv(
            name
        )

        if raw_value is None:
            raise RuntimeError(
                (
                    f"{name} must be configured "
                    "when Gmail notifications "
                    "are enabled"
                )
            )

        value = (
            raw_value.strip()
        )

        if (
            not value
            or value == "CHANGE_ME"
        ):
            raise RuntimeError(
                (
                    f"{name} must be configured "
                    "when Gmail notifications "
                    "are enabled"
                )
            )