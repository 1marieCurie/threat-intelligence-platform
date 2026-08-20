from __future__ import annotations

from application.ports.outbound.notification_port import (
    AlertNotification,
    NotificationDeliveryError,
    NotificationPort,
)


class DisabledNotificationAdapter(
    NotificationPort
):
    """
    Adapter utilisé tant que la livraison Gmail
    n'est pas activée dans le runtime.

    Une tentative d'envoi échoue de manière contrôlée.

    AlertEvaluationService conserve alors l'alerte
    persistée et marque son état de notification
    comme failed.

    Cela évite de déclarer faussement une notification
    comme envoyée pendant le développement.
    """

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

        raise NotificationDeliveryError(
            "Notification delivery is disabled "
            "in the current runtime"
        )