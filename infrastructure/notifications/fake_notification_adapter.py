from __future__ import annotations

from application.ports.outbound.notification_port import (
    AlertNotification,
    NotificationDeliveryError,
    NotificationPort,
)


class FakeNotificationAdapter(
    NotificationPort
):
    """
    Adapter de test déterministe.

    Par défaut :
    - tout envoi réussit ;
    - les notifications sont conservées en mémoire.

    fail_for_alert_ids permet de simuler
    des erreurs d'envoi contrôlées.
    """

    def __init__(
        self,
        *,
        fail_for_alert_ids: (
            frozenset[object]
            | None
        ) = None,
    ) -> None:
        self._fail_for_alert_ids = (
            fail_for_alert_ids
            or frozenset()
        )

        self.sent_notifications: list[
            AlertNotification
        ] = []

        self.attempted_notifications: list[
            AlertNotification
        ] = []

    def send(
        self,
        notification: AlertNotification,
    ) -> None:
        if not isinstance(
            notification,
            AlertNotification,
        ):
            raise TypeError(
                "notification must be "
                "an AlertNotification"
            )

        self.attempted_notifications.append(
            notification
        )

        if (
            notification.alert_id
            in self._fail_for_alert_ids
        ):
            raise NotificationDeliveryError(
                "Simulated notification "
                "delivery failure"
            )

        self.sent_notifications.append(
            notification
        )