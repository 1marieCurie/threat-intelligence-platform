from __future__ import annotations

from datetime import (
    UTC,
    datetime,
)
from unittest.mock import (
    MagicMock,
)
from uuid import uuid4

import pytest
from sqlalchemy.exc import (
    SQLAlchemyError,
)

from application.ports.outbound.alert_read_repository import (
    AlertReadRepositoryError,
)
from infrastructure.persistence.sqlalchemy.readers.alert_read_repository import (
    SqlAlchemyAlertReadRepository,
)


def test_list_alerts_maps_rows(
) -> None:
    organization_id = uuid4()

    alert_id = uuid4()
    machine_id = uuid4()
    canonical_id = uuid4()

    created_at = datetime(
        2026,
        8,
        20,
        12,
        0,
        tzinfo=UTC,
    )

    sent_at = datetime(
        2026,
        8,
        20,
        12,
        1,
        tzinfo=UTC,
    )

    session = MagicMock()

    (
        session
        .execute
        .return_value
        .tuples
        .return_value
        .all
        .return_value
    ) = [
        (
            alert_id,
            (
                "priority_transition_"
                "to_critical"
            ),
            "sent",
            created_at,
            sent_at,
            machine_id,
            "PC-FINANCE-01",
            canonical_id,
            "CVE-2026-12345",
            "Example Software",
            "4.2.1",
            "CRITICAL",
            True,
        ),
    ]

    session_factory = MagicMock()

    (
        session_factory
        .return_value
        .__enter__
        .return_value
    ) = session

    repository = (
        SqlAlchemyAlertReadRepository(
            session_factory
        )
    )

    result = repository.list_alerts(
        organization_id=(
            organization_id
        )
    )

    assert len(
        result
    ) == 1

    alert = result[0]

    assert (
        alert.alert_id
        == alert_id
    )

    assert (
        alert.alert_type
        == (
            "priority_transition_"
            "to_critical"
        )
    )

    assert (
        alert.status
        == "sent"
    )

    assert (
        alert.created_at
        == created_at
    )

    assert (
        alert.sent_at
        == sent_at
    )

    assert (
        alert.machine_id
        == machine_id
    )

    assert (
        alert.machine_hostname
        == "PC-FINANCE-01"
    )

    assert (
        alert.canonical_vulnerability_id
        == canonical_id
    )

    assert (
        alert.primary_identifier
        == "CVE-2026-12345"
    )

    assert (
        alert.component_name
        == "Example Software"
    )

    assert (
        alert.component_version
        == "4.2.1"
    )

    assert (
        alert.current_priority
        == "CRITICAL"
    )

    assert (
        alert.is_kev
        is True
    )

    (
        session
        .execute
        .assert_called_once()
    )

    statement = (
        session
        .execute
        .call_args
        .args[0]
    )

    assert organization_id in (
        statement
        .compile()
        .params
        .values()
    )


def test_list_alerts_preserves_alert_when_exposure_is_missing(
) -> None:
    organization_id = uuid4()

    alert_id = uuid4()
    machine_id = uuid4()
    canonical_id = uuid4()

    created_at = datetime(
        2026,
        8,
        20,
        12,
        0,
        tzinfo=UTC,
    )

    session = MagicMock()

    (
        session
        .execute
        .return_value
        .tuples
        .return_value
        .all
        .return_value
    ) = [
        (
            alert_id,
            (
                "new_confirmed_"
                "critical_exposure"
            ),
            "failed",
            created_at,
            None,
            machine_id,
            "SERVER-01",
            canonical_id,
            "CVE-2026-99999",
            None,
            None,
            None,
            None,
        ),
    ]

    session_factory = MagicMock()

    (
        session_factory
        .return_value
        .__enter__
        .return_value
    ) = session

    repository = (
        SqlAlchemyAlertReadRepository(
            session_factory
        )
    )

    result = repository.list_alerts(
        organization_id=(
            organization_id
        )
    )

    assert len(
        result
    ) == 1

    alert = result[0]

    assert (
        alert.primary_identifier
        == "CVE-2026-99999"
    )

    assert (
        alert.component_name
        is None
    )

    assert (
        alert.component_version
        is None
    )

    assert (
        alert.current_priority
        is None
    )

    assert (
        alert.is_kev
        is None
    )


def test_list_alerts_maps_sqlalchemy_error(
) -> None:
    organization_id = uuid4()

    session = MagicMock()

    session.execute.side_effect = (
        SQLAlchemyError(
            "database unavailable"
        )
    )

    session_factory = MagicMock()

    (
        session_factory
        .return_value
        .__enter__
        .return_value
    ) = session

    repository = (
        SqlAlchemyAlertReadRepository(
            session_factory
        )
    )

    with pytest.raises(
        AlertReadRepositoryError,
        match="Unable to read alerts",
    ):
        repository.list_alerts(
            organization_id=(
                organization_id
            )
        )