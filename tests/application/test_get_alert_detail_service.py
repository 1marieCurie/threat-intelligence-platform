from __future__ import annotations

from datetime import (
    UTC,
    datetime,
)
from uuid import (
    UUID,
    uuid4,
)

import pytest

from application.models.alert_view import (
    AlertDetail,
    AlertIdentifierView,
    AlertMachineView,
    AlertRecipientView,
    AlertWeaknessView,
)
from application.services.get_alert_detail_service import (
    GetAlertDetailService,
)


class FakeAlertRepository:
    def __init__(
        self,
        *,
        detail: AlertDetail | None = None,
    ) -> None:
        self.detail = detail

        self.organization_id: (
            UUID | None
        ) = None

        self.alert_id: (
            UUID | None
        ) = None

    def list_alerts(
        self,
        *,
        organization_id: UUID,
    ) -> tuple:
        return ()

    def get_alert_detail(
        self,
        *,
        organization_id: UUID,
        alert_id: UUID,
    ) -> AlertDetail | None:
        self.organization_id = (
            organization_id
        )

        self.alert_id = (
            alert_id
        )

        return self.detail


def build_alert_detail(
) -> AlertDetail:
    alert_id = uuid4()

    organization_machine_id = (
        uuid4()
    )

    canonical_id = uuid4()

    recipient_id = uuid4()

    now = datetime.now(
        UTC
    )

    return AlertDetail(
        alert_id=alert_id,
        alert_type=(
            "new_confirmed_critical_exposure"
        ),
        status="pending",
        created_at=now,
        sent_at=None,
        recipient=(
            AlertRecipientView(
                user_id=recipient_id,
                email=(
                    "security@example.test"
                ),
                display_name=(
                    "Security Responsible"
                ),
            )
        ),
        machine=(
            AlertMachineView(
                machine_id=(
                    organization_machine_id
                ),
                hostname=(
                    "WORKSTATION-01"
                ),
                os_name=(
                    "Microsoft Windows"
                ),
                os_version="11",
                architecture="x86_64",
            )
        ),
        canonical_vulnerability_id=(
            canonical_id
        ),
        primary_identifier=(
            "CVE-2026-1234"
        ),
        identifiers=(
            AlertIdentifierView(
                namespace="CVE",
                value="CVE-2026-1234",
                is_primary=True,
            ),
            AlertIdentifierView(
                namespace="GHSA",
                value=(
                    "GHSA-AAAA-BBBB-CCCC"
                ),
                is_primary=False,
            ),
        ),
        component=None,
        exposure=None,
        epss_score=0.42,
        epss_percentile=0.95,
        cvss_score=9.8,
        cvss_version="3.1",
        cvss_vector=(
            "CVSS:3.1/AV:N/AC:L/"
            "PR:N/UI:N/S:U/C:H/I:H/A:H"
        ),
        cvss_source_name="nvd",
        cvss_source_role="NVD",
        weaknesses=(
            AlertWeaknessView(
                cwe_id="CWE-79",
                name=(
                    "Improper Neutralization "
                    "of Input During Web Page "
                    "Generation"
                ),
                description=(
                    "Example CWE description."
                ),
            ),
        ),
    )


def test_constructor_rejects_none_repository(
) -> None:
    with pytest.raises(
        ValueError,
        match=(
            "repository must not be None"
        ),
    ):
        GetAlertDetailService(
            repository=None,  # type: ignore[arg-type]
        )


def test_rejects_invalid_organization_id(
) -> None:
    service = (
        GetAlertDetailService(
            repository=(
                FakeAlertRepository()
            )
        )
    )

    with pytest.raises(
        TypeError,
        match=(
            "organization_id must be UUID"
        ),
    ):
        service.get_alert(
            organization_id=(
                "invalid"  # type: ignore[arg-type]
            ),
            alert_id=uuid4(),
        )


def test_rejects_invalid_alert_id(
) -> None:
    service = (
        GetAlertDetailService(
            repository=(
                FakeAlertRepository()
            )
        )
    )

    with pytest.raises(
        TypeError,
        match=(
            "alert_id must be UUID"
        ),
    ):
        service.get_alert(
            organization_id=uuid4(),
            alert_id=(
                "invalid"  # type: ignore[arg-type]
            ),
        )


def test_delegates_with_tenant_scope(
) -> None:
    organization_id = uuid4()
    alert_id = uuid4()

    repository = (
        FakeAlertRepository()
    )

    service = (
        GetAlertDetailService(
            repository=repository
        )
    )

    result = (
        service.get_alert(
            organization_id=(
                organization_id
            ),
            alert_id=alert_id,
        )
    )

    assert result is None

    assert (
        repository.organization_id
        == organization_id
    )

    assert (
        repository.alert_id
        == alert_id
    )


def test_returns_repository_detail(
) -> None:
    detail = (
        build_alert_detail()
    )

    repository = (
        FakeAlertRepository(
            detail=detail
        )
    )

    service = (
        GetAlertDetailService(
            repository=repository
        )
    )

    result = (
        service.get_alert(
            organization_id=uuid4(),
            alert_id=detail.alert_id,
        )
    )

    assert result == detail