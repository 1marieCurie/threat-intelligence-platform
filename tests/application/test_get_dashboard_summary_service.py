from uuid import uuid4

from application.models.dashboard import (
    DashboardMetrics,
    DashboardPriorityDistribution,
)
from application.services.get_dashboard_summary_service import (
    GetDashboardSummaryService,
)


class FakeDashboardRepository:
    def __init__(
        self,
        metrics: DashboardMetrics,
    ) -> None:
        self.metrics = metrics
        self.organization_id = None

    def read_metrics(
        self,
        *,
        organization_id,
    ):
        self.organization_id = (
            organization_id
        )

        return self.metrics


def test_builds_priority_actions() -> None:
    organization_id = uuid4()

    repository = (
        FakeDashboardRepository(
            DashboardMetrics(
                machine_count=4,
                component_count=30,
                confirmed_exposure_count=8,
                potential_exposure_count=3,
                critical_exposure_count=2,
                kev_exposure_count=2,
                pending_alert_count=1,
                failed_alert_count=1,
                critical_confirmed_exposure_count=2,
                confirmed_kev_exposure_count=1,
                priority_distribution=(
                    DashboardPriorityDistribution(
                        low=1,
                        medium=3,
                        high=5,
                        critical=2,
                    )
                ),
                top_machines=(),
                latest_alerts=(),
            )
        )
    )

    service = (
        GetDashboardSummaryService(
            repository=repository
        )
    )

    result = service.get_summary(
        organization_id=organization_id
    )

    assert (
        repository.organization_id
        == organization_id
    )

    assert len(
        result.priority_actions
    ) == 3

    assert (
        result.priority_actions[0].kind
        == "critical_confirmed"
    )

    assert (
        result.priority_actions[1].kind
        == "confirmed_kev"
    )

    assert (
        result.priority_actions[2].kind
        == "notification_attention"
    )


def test_returns_no_actions_when_nothing_requires_attention(
) -> None:
    repository = (
        FakeDashboardRepository(
            DashboardMetrics(
                machine_count=0,
                component_count=0,
                confirmed_exposure_count=0,
                potential_exposure_count=0,
                critical_exposure_count=0,
                kev_exposure_count=0,
                pending_alert_count=0,
                failed_alert_count=0,
                critical_confirmed_exposure_count=0,
                confirmed_kev_exposure_count=0,
                priority_distribution=(
                    DashboardPriorityDistribution(
                        low=0,
                        medium=0,
                        high=0,
                        critical=0,
                    )
                ),
                top_machines=(),
                latest_alerts=(),
            )
        )
    )

    service = (
        GetDashboardSummaryService(
            repository=repository
        )
    )

    result = service.get_summary(
        organization_id=uuid4()
    )

    assert (
        result.priority_actions
        == ()
    )