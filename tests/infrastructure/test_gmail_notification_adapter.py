from __future__ import annotations

import base64
import json
from email import policy
from email.parser import BytesParser
from typing import cast
from unittest.mock import Mock
from uuid import uuid4

import pytest
import requests

from application.ports.outbound.notification_port import (
    AlertNotification,
    NotificationDeliveryError,
)
from infrastructure.notifications.gmail_notification_adapter import (
    GmailNotificationAdapter,
    GmailNotificationConfig,
)


def _config(
) -> GmailNotificationConfig:
    return GmailNotificationConfig(
        client_id="test-client-id",
        client_secret="test-client-secret",
        refresh_token="test-refresh-token",
        sender_email=(
            "security@example.test"
        ),
        sender_name=(
            "Threat Intelligence Platform"
        ),
        timeout_seconds=10,
    )


def _notification(
) -> AlertNotification:
    return AlertNotification(
        alert_id=uuid4(),
        organization_id=uuid4(),
        machine_id=uuid4(),
        vulnerability_exposure_id=uuid4(),
        canonical_vulnerability_id=uuid4(),
        alert_type=(
            "priority_transition_to_critical"
        ),
        recipient_user_id=uuid4(),
        recipient_email=(
            "responsible@example.test"
        ),
        recipient_display_name=(
            "Security Responsible"
        ),
    )


def _json_response(
    *,
    status_code: int,
    payload: dict[
        str,
        object,
    ],
    url: str,
) -> requests.Response:
    response = requests.Response()

    response.status_code = ( # pyright: ignore[reportAttributeAccessIssue]
        status_code
    )

    response.url = url # pyright: ignore[reportAttributeAccessIssue]

    response.headers[
        "Content-Type"
    ] = "application/json"

    response._content = (
        json.dumps(
            payload
        )
        .encode(
            "utf-8"
        )
    )

    return response


def _session_mock(
) -> requests.Session:
    return cast(
        requests.Session,
        Mock(
            spec=requests.Session
        ),
    )


def test_gmail_adapter_sends_base64url_mime_message(
) -> None:
    session = _session_mock()

    token_response = _json_response(
        status_code=200,
        payload={
            "access_token": (
                "test-access-token"
            ),
            "expires_in": 3600,
            "token_type": "Bearer",
        },
        url=(
            GmailNotificationAdapter
            .TOKEN_ENDPOINT
        ),
    )

    send_response = _json_response(
        status_code=200,
        payload={
            "id": "gmail-message-id",
        },
        url=(
            GmailNotificationAdapter
            .SEND_ENDPOINT
        ),
    )

    session.post.side_effect = [  # type: ignore[attr-defined]
        token_response,
        send_response,
    ]

    adapter = (
        GmailNotificationAdapter(
            config=_config(),
            http_session=session,
        )
    )

    notification = (
        _notification()
    )

    adapter.send(
        notification
    )

    assert (
        session.post.call_count  # type: ignore[attr-defined]
        == 2
    )

    token_call = (
        session
        .post
        .call_args_list[0]  # type: ignore[attr-defined]
    )

    assert (
        token_call.args[0]
        == (
            GmailNotificationAdapter
            .TOKEN_ENDPOINT
        )
    )

    assert (
        token_call.kwargs[
            "data"
        ][
            "grant_type"
        ]
        == "refresh_token"
    )

    assert (
        token_call.kwargs[
            "data"
        ][
            "client_id"
        ]
        == "test-client-id"
    )

    send_call = (
        session
        .post
        .call_args_list[1]  # type: ignore[attr-defined]
    )

    assert (
        send_call.args[0]
        == (
            GmailNotificationAdapter
            .SEND_ENDPOINT
        )
    )

    assert (
        send_call.kwargs[
            "headers"
        ][
            "Authorization"
        ]
        == "Bearer test-access-token"
    )

    encoded_raw = (
        send_call.kwargs[
            "json"
        ][
            "raw"
        ]
    )

    decoded_raw = (
        base64
        .urlsafe_b64decode(
            encoded_raw
        )
    )

    message = (
        BytesParser(
            policy=policy.default
        )
        .parsebytes(
            decoded_raw
        )
    )

    assert (
        str(
            message["To"]
        )
        == (
            "Security Responsible "
            "<responsible@example.test>"
        )
    )

    assert (
        str(
            message["From"]
        )
        == (
            "Threat Intelligence Platform "
            "<security@example.test>"
        )
    )

    assert (
        str(
            message["Subject"]
        )
        == (
            "[Threat Intelligence] "
            "Priorité passée à CRITICAL"
        )
    )

    assert (
        str(
            message[
                "X-Threat-Intel-Alert-ID"
            ]
        )
        == str(
            notification.alert_id
        )
    )

    body = (
        message.get_body(
            preferencelist=(
                "plain",
            )
        )
    )

    assert body is not None

    content = (
        body.get_content()
    )

    assert (
        str(
            notification.machine_id
        )
        in content
    )

    assert (
        str(
            notification
            .vulnerability_exposure_id
        )
        in content
    )


def test_gmail_adapter_reuses_cached_access_token(
) -> None:
    session = _session_mock()

    token_response = _json_response(
        status_code=200,
        payload={
            "access_token": (
                "cached-token"
            ),
            "expires_in": 3600,
        },
        url=(
            GmailNotificationAdapter
            .TOKEN_ENDPOINT
        ),
    )

    first_send_response = (
        _json_response(
            status_code=200,
            payload={
                "id": "message-1",
            },
            url=(
                GmailNotificationAdapter
                .SEND_ENDPOINT
            ),
        )
    )

    second_send_response = (
        _json_response(
            status_code=200,
            payload={
                "id": "message-2",
            },
            url=(
                GmailNotificationAdapter
                .SEND_ENDPOINT
            ),
        )
    )

    session.post.side_effect = [  # type: ignore[attr-defined]
        token_response,
        first_send_response,
        second_send_response,
    ]

    adapter = (
        GmailNotificationAdapter(
            config=_config(),
            http_session=session,
        )
    )

    adapter.send(
        _notification()
    )

    adapter.send(
        _notification()
    )

    # 1 refresh OAuth + 2 sends Gmail.
    assert (
        session.post.call_count  # type: ignore[attr-defined]
        == 3
    )


def test_gmail_adapter_wraps_token_failure_without_leaking_secrets(
) -> None:
    session = _session_mock()

    session.post.return_value = (  # type: ignore[attr-defined]
        _json_response(
            status_code=400,
            payload={
                "error": (
                    "invalid_grant"
                ),
            },
            url=(
                GmailNotificationAdapter
                .TOKEN_ENDPOINT
            ),
        )
    )

    config = _config()

    adapter = (
        GmailNotificationAdapter(
            config=config,
            http_session=session,
        )
    )

    with pytest.raises(
        NotificationDeliveryError,
        match=(
            "Unable to obtain Gmail "
            "OAuth access token"
        ),
    ) as exc_info:
        adapter.send(
            _notification()
        )

    message = str(
        exc_info.value
    )

    assert (
        config.client_secret
        not in message
    )

    assert (
        config.refresh_token
        not in message
    )

    assert (
        session.post.call_count  # type: ignore[attr-defined]
        == 1
    )


def test_gmail_adapter_wraps_send_failure(
) -> None:
    session = _session_mock()

    session.post.side_effect = [  # type: ignore[attr-defined]
        _json_response(
            status_code=200,
            payload={
                "access_token": (
                    "test-token"
                ),
                "expires_in": 3600,
            },
            url=(
                GmailNotificationAdapter
                .TOKEN_ENDPOINT
            ),
        ),
        _json_response(
            status_code=403,
            payload={
                "error": {
                    "message": (
                        "Forbidden"
                    ),
                }
            },
            url=(
                GmailNotificationAdapter
                .SEND_ENDPOINT
            ),
        ),
    ]

    adapter = (
        GmailNotificationAdapter(
            config=_config(),
            http_session=session,
        )
    )

    with pytest.raises(
        NotificationDeliveryError,
        match=(
            "Gmail API request failed "
            "with HTTP 403"
        ),
    ):
        adapter.send(
            _notification()
        )


def test_gmail_adapter_rejects_unknown_alert_type(
) -> None:
    session = _session_mock()

    adapter = (
        GmailNotificationAdapter(
            config=_config(),
            http_session=session,
        )
    )

    notification = (
        AlertNotification(
            alert_id=uuid4(),
            organization_id=uuid4(),
            machine_id=uuid4(),
            vulnerability_exposure_id=(
                uuid4()
            ),
            canonical_vulnerability_id=(
                uuid4()
            ),
            alert_type=(
                "unsupported_alert"
            ),
            recipient_user_id=uuid4(),
            recipient_email=(
                "responsible@example.test"
            ),
            recipient_display_name=(
                "Responsible"
            ),
        )
    )

    # Le token est demandé avant la construction du
    # message dans send(), donc on fournit une réponse.
    session.post.return_value = (  # type: ignore[attr-defined]
        _json_response(
            status_code=200,
            payload={
                "access_token": (
                    "test-token"
                ),
                "expires_in": 3600,
            },
            url=(
                GmailNotificationAdapter
                .TOKEN_ENDPOINT
            ),
        )
    )

    with pytest.raises(
        NotificationDeliveryError,
        match="Unsupported alert type",
    ):
        adapter.send(
            notification
        )