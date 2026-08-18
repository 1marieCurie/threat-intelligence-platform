from __future__ import annotations

import base64
import os
import threading
import time
from dataclasses import dataclass
from email.headerregistry import Address
from email.message import EmailMessage

import requests
from dotenv import load_dotenv

from application.ports.outbound.notification_port import (
    AlertNotification,
    NotificationDeliveryError,
    NotificationPort,
)


@dataclass(
    frozen=True,
    slots=True,
)
class GmailNotificationConfig:
    client_id: str
    client_secret: str
    refresh_token: str
    sender_email: str
    sender_name: str = (
        "Threat Intelligence Platform"
    )
    timeout_seconds: float = 10.0

    def __post_init__(
        self,
    ) -> None:
        required_values = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "refresh_token": self.refresh_token,
            "sender_email": self.sender_email,
        }

        for (
            field_name,
            value,
        ) in required_values.items():
            if (
                not isinstance(
                    value,
                    str,
                )
                or not value.strip()
            ):
                raise ValueError(
                    f"{field_name} must be "
                    "a non-empty string"
                )

        if (
            not isinstance(
                self.sender_name,
                str,
            )
            or not self.sender_name.strip()
        ):
            raise ValueError(
                "sender_name must be "
                "a non-empty string"
            )

        if (
            "\n" in self.sender_name
            or "\r" in self.sender_name
            or "\n" in self.sender_email
            or "\r" in self.sender_email
        ):
            raise ValueError(
                "Gmail sender fields must not "
                "contain newlines"
            )

        try:
            Address(
                addr_spec=(
                    self.sender_email
                    .strip()
                )
            )

        except ValueError as error:
            raise ValueError(
                "sender_email is invalid"
            ) from error

        if isinstance(
            self.timeout_seconds,
            bool,
        ):
            raise TypeError(
                "timeout_seconds must be numeric"
            )

        if not isinstance(
            self.timeout_seconds,
            (int, float),
        ):
            raise TypeError(
                "timeout_seconds must be numeric"
            )

        if self.timeout_seconds <= 0:
            raise ValueError(
                "timeout_seconds must be > 0"
            )

    @classmethod
    def from_env(
        cls,
    ) -> GmailNotificationConfig:
        """
        Charge la configuration Gmail depuis .env.

        Aucun secret ne doit être codé en dur.
        """

        load_dotenv()

        timeout_raw = os.getenv(
            "TIP_GMAIL_TIMEOUT_SECONDS",
            "10",
        )

        try:
            timeout_seconds = float(
                timeout_raw
            )

        except ValueError as error:
            raise ValueError(
                "TIP_GMAIL_TIMEOUT_SECONDS "
                "must be numeric"
            ) from error

        return cls(
            client_id=(
                os.getenv(
                    "TIP_GMAIL_CLIENT_ID",
                    "",
                )
            ),
            client_secret=(
                os.getenv(
                    "TIP_GMAIL_CLIENT_SECRET",
                    "",
                )
            ),
            refresh_token=(
                os.getenv(
                    "TIP_GMAIL_REFRESH_TOKEN",
                    "",
                )
            ),
            sender_email=(
                os.getenv(
                    "TIP_GMAIL_SENDER_EMAIL",
                    "",
                )
            ),
            sender_name=(
                os.getenv(
                    "TIP_GMAIL_SENDER_NAME",
                    "Threat Intelligence Platform",
                )
            ),
            timeout_seconds=(
                timeout_seconds
            ),
        )


class GmailNotificationAdapter(
    NotificationPort
):
    """
    Adapter Gmail API V1.

    - OAuth 2.0 avec refresh token ;
    - scope minimal attendu : gmail.send ;
    - cache mémoire du token d'accès ;
    - aucun retry automatique d'un email afin
      d'éviter un double envoi après timeout ;
    - aucun secret inclus dans les exceptions.
    """

    TOKEN_ENDPOINT = (
        "https://oauth2.googleapis.com/token"
    )

    SEND_ENDPOINT = (
        "https://gmail.googleapis.com/"
        "gmail/v1/users/me/messages/send"
    )

    REQUIRED_SCOPE = (
        "https://www.googleapis.com/auth/"
        "gmail.send"
    )

    _TOKEN_EXPIRY_MARGIN_SECONDS = 60.0

    _SUBJECT_BY_ALERT_TYPE = {
        (
            "new_confirmed_critical_exposure"
        ): (
            "[Threat Intelligence] "
            "Nouvelle exposition critique confirmée"
        ),
        (
            "confirmed_exposure_entered_kev"
        ): (
            "[Threat Intelligence] "
            "Exposition confirmée entrée dans CISA KEV"
        ),
        (
            "priority_transition_to_critical"
        ): (
            "[Threat Intelligence] "
            "Priorité passée à CRITICAL"
        ),
    }

    def __init__(
        self,
        *,
        config: GmailNotificationConfig,
        http_session: (
            requests.Session
            | None
        ) = None,
    ) -> None:
        if not isinstance(
            config,
            GmailNotificationConfig,
        ):
            raise TypeError(
                "config must be a "
                "GmailNotificationConfig"
            )

        self._config = config

        self._http_session = (
            http_session
            or requests.Session()
        )

        self._access_token: (
            str
            | None
        ) = None

        self._access_token_expires_at = (
            0.0
        )

        self._token_lock = (
            threading.Lock()
        )

    @classmethod
    def from_env(
        cls,
    ) -> GmailNotificationAdapter:
        return cls(
            config=(
                GmailNotificationConfig
                .from_env()
            )
        )

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

        access_token = (
            self._get_access_token()
        )

        raw_message = (
            self._build_raw_message(
                notification
            )
        )

        try:
            response = (
                self._http_session.post(
                    self.SEND_ENDPOINT,
                    headers={
                        "Authorization": (
                            f"Bearer "
                            f"{access_token}"
                        ),
                        "Accept": (
                            "application/json"
                        ),
                        "Content-Type": (
                            "application/json"
                        ),
                    },
                    json={
                        "raw": raw_message,
                    },
                    timeout=(
                        self
                        ._config
                        .timeout_seconds
                    ),
                )
            )

            response.raise_for_status()

        except requests.RequestException as error:
            status_code = (
                error.response.status_code
                if error.response
                is not None
                else None
            )

            detail = (
                "Gmail API request failed"
            )

            if status_code is not None:
                detail += (
                    f" with HTTP "
                    f"{status_code}"
                )

            raise (
                NotificationDeliveryError(
                    detail
                )
            ) from error

    def _get_access_token(
        self,
    ) -> str:
        with self._token_lock:
            if (
                self._access_token
                is not None
                and time.monotonic()
                < self
                ._access_token_expires_at
            ):
                return (
                    self._access_token
                )

            return (
                self._refresh_access_token()
            )

    def _refresh_access_token(
        self,
    ) -> str:
        try:
            response = (
                self._http_session.post(
                    self.TOKEN_ENDPOINT,
                    data={
                        "client_id": (
                            self
                            ._config
                            .client_id
                        ),
                        "client_secret": (
                            self
                            ._config
                            .client_secret
                        ),
                        "refresh_token": (
                            self
                            ._config
                            .refresh_token
                        ),
                        "grant_type": (
                            "refresh_token"
                        ),
                    },
                    headers={
                        "Accept": (
                            "application/json"
                        ),
                    },
                    timeout=(
                        self
                        ._config
                        .timeout_seconds
                    ),
                )
            )

            response.raise_for_status()

            payload = response.json()

        except (
            requests.RequestException,
            ValueError,
        ) as error:
            status_code = (
                error.response.status_code
                if isinstance(
                    error,
                    requests.RequestException,
                )
                and error.response
                is not None
                else None
            )

            detail = (
                "Unable to obtain Gmail "
                "OAuth access token"
            )

            if status_code is not None:
                detail += (
                    f" with HTTP "
                    f"{status_code}"
                )

            raise (
                NotificationDeliveryError(
                    detail
                )
            ) from error

        if not isinstance(
            payload,
            dict,
        ):
            raise (
                NotificationDeliveryError(
                    "Invalid Gmail OAuth "
                    "token response"
                )
            )

        access_token = payload.get(
            "access_token"
        )

        if (
            not isinstance(
                access_token,
                str,
            )
            or not access_token.strip()
        ):
            raise (
                NotificationDeliveryError(
                    "Gmail OAuth response "
                    "does not contain "
                    "an access token"
                )
            )

        access_token = (
            access_token.strip()
        )

        expires_in = payload.get(
            "expires_in"
        )

        self._access_token = (
            access_token
        )

        self._access_token_expires_at = (
            0.0
        )

        if (
            isinstance(
                expires_in,
                (int, float),
            )
            and not isinstance(
                expires_in,
                bool,
            )
            and expires_in > 0
        ):
            cache_duration = max(
                float(
                    expires_in
                )
                - (
                    self
                    ._TOKEN_EXPIRY_MARGIN_SECONDS
                ),
                0.0,
            )

            self._access_token_expires_at = (
                time.monotonic()
                + cache_duration
            )

        return access_token

    def _build_raw_message(
        self,
        notification: AlertNotification,
    ) -> str:
        subject = (
            self
            ._SUBJECT_BY_ALERT_TYPE
            .get(
                notification.alert_type
            )
        )

        if subject is None:
            raise (
                NotificationDeliveryError(
                    "Unsupported alert type "
                    "for Gmail notification"
                )
            )

        try:
            recipient = Address(
                display_name=(
                    notification
                    .recipient_display_name
                    .strip()
                ),
                addr_spec=(
                    notification
                    .recipient_email
                    .strip()
                ),
            )

            sender = Address(
                display_name=(
                    self
                    ._config
                    .sender_name
                    .strip()
                ),
                addr_spec=(
                    self
                    ._config
                    .sender_email
                    .strip()
                ),
            )

            message = EmailMessage()

            message["To"] = recipient
            message["From"] = sender
            message["Subject"] = subject

            message[
                "X-Threat-Intel-Alert-ID"
            ] = str(
                notification.alert_id
            )

            message.set_content(
                self._build_body(
                    notification
                )
            )

            encoded = (
                base64
                .urlsafe_b64encode(
                    message.as_bytes()
                )
                .decode(
                    "ascii"
                )
            )

        except (
            TypeError,
            ValueError,
        ) as error:
            raise (
                NotificationDeliveryError(
                    "Unable to build Gmail "
                    "notification message"
                )
            ) from error

        return encoded

    @staticmethod
    def _build_body(
        notification: AlertNotification,
    ) -> str:
        display_name = (
            notification
            .recipient_display_name
            .strip()
        )

        greeting = (
            f"Bonjour {display_name},"
            if display_name
            else "Bonjour,"
        )

        alert_description = {
            (
                "new_confirmed_critical_exposure"
            ): (
                "Une nouvelle exposition "
                "critique confirmée a été détectée."
            ),
            (
                "confirmed_exposure_entered_kev"
            ): (
                "Une exposition confirmée "
                "est désormais associée au "
                "catalogue CISA KEV."
            ),
            (
                "priority_transition_to_critical"
            ): (
                "La priorité d'une exposition "
                "est passée au niveau CRITICAL."
            ),
        }.get(
            notification.alert_type,
            (
                "Une alerte de sécurité "
                "a été détectée."
            ),
        )

        return "\n".join(
            (
                greeting,
                "",
                alert_description,
                "",
                (
                    "Machine ID : "
                    f"{notification.machine_id}"
                ),
                (
                    "Exposure ID : "
                    f"{notification.vulnerability_exposure_id}"
                ),
                (
                    "Canonical vulnerability ID : "
                    f"{notification.canonical_vulnerability_id}"
                ),
                (
                    "Alert ID : "
                    f"{notification.alert_id}"
                ),
                "",
                (
                    "Consultez la Threat "
                    "Intelligence Platform pour "
                    "analyser cette exposition."
                ),
                "",
                (
                    "Threat Intelligence Platform"
                ),
            )
        )