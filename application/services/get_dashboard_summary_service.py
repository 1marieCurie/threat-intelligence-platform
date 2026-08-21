from __future__ import annotations

from uuid import UUID

from application.models.dashboard import (
    DashboardPriorityAction,
    DashboardSummary,
)
from application.ports.outbound.dashboard_read_repository import (
    DashboardReadRepository,
)


class GetDashboardSummaryService:
    def __init__(
        self,
        *,
        repository: DashboardReadRepository,
    ) -> None:
        if repository is None:
            raise ValueError(
                "repository must not be None"
            )

        self._repository = repository

    def get_summary(
        self,
        *,
        organization_id: UUID,
    ) -> DashboardSummary:
        if not isinstance(
            organization_id,
            UUID,
        ):
            raise TypeError(
                "organization_id must be UUID"
            )

        metrics = (
            self._repository.read_metrics(
                organization_id=(
                    organization_id
                )
            )
        )

        actions: list[
            DashboardPriorityAction
        ] = []

        if (
            metrics
            .critical_confirmed_exposure_count
            > 0
        ):
            actions.append(
                DashboardPriorityAction(
                    kind=(
                        "critical_confirmed"
                    ),
                    title=(
                        "Expositions critiques "
                        "confirmées"
                    ),
                    count=(
                        metrics
                        .critical_confirmed_exposure_count
                    ),
                    priority="CRITICAL",
                )
            )

        if (
            metrics
            .confirmed_kev_exposure_count
            > 0
        ):
            actions.append(
                DashboardPriorityAction(
                    kind="confirmed_kev",
                    title=(
                        "Expositions confirmées "
                        "présentes dans KEV"
                    ),
                    count=(
                        metrics
                        .confirmed_kev_exposure_count
                    ),
                    priority="CRITICAL",
                )
            )

        notification_attention_count = (
            metrics.pending_alert_count
            + metrics.failed_alert_count
        )

        if notification_attention_count > 0:
            actions.append(
                DashboardPriorityAction(
                    kind=(
                        "notification_attention"
                    ),
                    title=(
                        "Alertes nécessitant "
                        "une attention"
                    ),
                    count=(
                        notification_attention_count
                    ),
                    priority=(
                        "HIGH"
                        if (
                            metrics
                            .failed_alert_count
                            > 0
                        )
                        else "MEDIUM"
                    ),
                )
            )

        return DashboardSummary(
            machine_count=(
                metrics.machine_count
            ),
            component_count=(
                metrics.component_count
            ),
            confirmed_exposure_count=(
                metrics
                .confirmed_exposure_count
            ),
            potential_exposure_count=(
                metrics
                .potential_exposure_count
            ),
            critical_exposure_count=(
                metrics
                .critical_exposure_count
            ),
            kev_exposure_count=(
                metrics.kev_exposure_count
            ),
            pending_alert_count=(
                metrics.pending_alert_count
            ),
            failed_alert_count=(
                metrics.failed_alert_count
            ),
            priority_distribution=(
                metrics
                .priority_distribution
            ),
            top_machines=(
                metrics.top_machines
            ),
            priority_actions=tuple(
                actions
            ),
            latest_alerts=(
                metrics.latest_alerts
            ),
        )