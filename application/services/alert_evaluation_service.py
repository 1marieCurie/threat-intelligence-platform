from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from application.ports.outbound.alert_repository import (
    AlertSentUpdate,
    PendingAlertCreate,
)
from application.ports.outbound.alert_unit_of_work import (
    AlertUnitOfWork,
)
from application.ports.outbound.notification_port import (
    AlertNotification,
    NotificationDeliveryError,
    NotificationPort,
)
from application.services.alert_evaluation_policy_v1 import (
    AlertEvaluationPolicyV1,
)
from domain.alert import Alert


@dataclass(
    frozen=True,
    slots=True,
)
class ExposureAlertTransition:
    exposure_id: UUID
    canonical_vulnerability_id: UUID
    applicability_status: str

    is_new_exposure: bool

    previous_priority: str | None
    current_priority: str

    previous_is_kev: bool | None
    current_is_kev: bool


@dataclass(
    frozen=True,
    slots=True,
)
class AlertEvaluationResult:
    transition_count: int
    recipient_count: int
    candidate_event_count: int
    attempted_alert_count: int

    created_alerts: tuple[
        Alert,
        ...,
    ]

    sent_notification_count: int
    failed_notification_count: int

    @property
    def created_alert_count(
        self,
    ) -> int:
        return len(
            self.created_alerts
        )


class MissingSecurityResponsibleError(
    RuntimeError
):
    pass


class AlertEvaluationService:
    """
    Évalue, persiste et notifie les alertes V1.

    Ordre transactionnel :

        INSERT pending
            ↓
        COMMIT
            ↓
        NotificationPort.send()
            ↓
        sent / failed
            ↓
        COMMIT

    Une panne de notification ne peut donc pas supprimer
    l'alerte métier déjà persistée.
    """

    def __init__(
        self,
        *,
        unit_of_work: AlertUnitOfWork,
        notification_port: NotificationPort,
        policy: (
            AlertEvaluationPolicyV1
            | None
        ) = None,
    ) -> None:
        if unit_of_work is None:
            raise ValueError(
                "unit_of_work must not be None"
            )

        if notification_port is None:
            raise ValueError(
                "notification_port must not be None"
            )

        self._unit_of_work = unit_of_work

        self._notification_port = (
            notification_port
        )

        self._policy = (
            policy
            or AlertEvaluationPolicyV1()
        )

    def evaluate(
        self,
        *,
        organization_id: UUID,
        machine_id: UUID,
        transitions: Iterable[
            ExposureAlertTransition
        ],
        evaluated_at: datetime,
    ) -> AlertEvaluationResult:
        if not isinstance(
            organization_id,
            UUID,
        ):
            raise TypeError(
                "organization_id must be a UUID"
            )

        if not isinstance(
            machine_id,
            UUID,
        ):
            raise TypeError(
                "machine_id must be a UUID"
            )

        if not isinstance(
            evaluated_at,
            datetime,
        ):
            raise TypeError(
                "evaluated_at must be a datetime"
            )

        if (
            evaluated_at.tzinfo is None
            or evaluated_at.utcoffset()
            is None
        ):
            raise ValueError(
                "evaluated_at must be timezone-aware"
            )

        normalized_transitions = (
            self._normalize_transitions(
                transitions
            )
        )

        if not normalized_transitions:
            return AlertEvaluationResult(
                transition_count=0,
                recipient_count=0,
                candidate_event_count=0,
                attempted_alert_count=0,
                created_alerts=(),
                sent_notification_count=0,
                failed_notification_count=0,
            )

        with self._unit_of_work as unit_of_work:
            recipients = (
                unit_of_work
                .security_responsibles
                .find_active_by_organization_id(
                    organization_id=(
                        organization_id
                    )
                )
            )

            if not recipients:
                raise (
                    MissingSecurityResponsibleError(
                        "Organization has no active "
                        "security_responsible recipient"
                    )
                )

            recipients_by_id = {
                recipient.id: recipient
                for recipient in recipients
            }

            pending_alerts: list[
                PendingAlertCreate
            ] = []

            candidate_event_count = 0

            for transition in (
                normalized_transitions
            ):
                candidates = (
                    self._policy.evaluate(
                        exposure_id=(
                            transition.exposure_id
                        ),
                        applicability_status=(
                            transition
                            .applicability_status
                        ),
                        is_new_exposure=(
                            transition
                            .is_new_exposure
                        ),
                        previous_priority=(
                            transition
                            .previous_priority
                        ),
                        current_priority=(
                            transition
                            .current_priority
                        ),
                        previous_is_kev=(
                            transition
                            .previous_is_kev
                        ),
                        current_is_kev=(
                            transition
                            .current_is_kev
                        ),
                    )
                )

                candidate_event_count += len(
                    candidates
                )

                for candidate in candidates:
                    for recipient in recipients:
                        deduplication_key = (
                            f"{candidate.deduplication_key}"
                            f":recipient:"
                            f"{recipient.id}"
                        )

                        if len(
                            deduplication_key
                        ) > 255:
                            raise ValueError(
                                "deduplication_key exceeds "
                                "255 characters"
                            )

                        pending_alerts.append(
                            PendingAlertCreate(
                                organization_id=(
                                    organization_id
                                ),
                                machine_id=(
                                    machine_id
                                ),
                                vulnerability_exposure_id=(
                                    transition.exposure_id
                                ),
                                canonical_vulnerability_id=(
                                    transition
                                    .canonical_vulnerability_id
                                ),
                                alert_type=(
                                    candidate.alert_type
                                ),
                                recipient_user_id=(
                                    recipient.id
                                ),
                                deduplication_key=(
                                    deduplication_key
                                ),
                                created_at=(
                                    evaluated_at
                                ),
                            )
                        )

            if not pending_alerts:
                return AlertEvaluationResult(
                    transition_count=len(
                        normalized_transitions
                    ),
                    recipient_count=len(
                        recipients
                    ),
                    candidate_event_count=0,
                    attempted_alert_count=0,
                    created_alerts=(),
                    sent_notification_count=0,
                    failed_notification_count=0,
                )

            # =================================================
            # PHASE 1
            #
            # L'alerte métier est persistée avant toute tentative
            # d'envoi.
            # =================================================
            created_alerts = (
                unit_of_work
                .alerts
                .insert_pending_many(
                    alerts=tuple(
                        pending_alerts
                    )
                )
            )

            unit_of_work.commit()

            # =================================================
            # Si PostgreSQL a tout dédupliqué, aucune notification
            # ne doit être renvoyée.
            # =================================================
            if not created_alerts:
                return AlertEvaluationResult(
                    transition_count=len(
                        normalized_transitions
                    ),
                    recipient_count=len(
                        recipients
                    ),
                    candidate_event_count=(
                        candidate_event_count
                    ),
                    attempted_alert_count=len(
                        pending_alerts
                    ),
                    created_alerts=(),
                    sent_notification_count=0,
                    failed_notification_count=0,
                )

            sent_updates: list[
                AlertSentUpdate
            ] = []

            failed_alert_ids: list[
                UUID
            ] = []

            # =================================================
            # PHASE 2
            #
            # On notifie uniquement les alertes réellement
            # insérées. Les alertes dédupliquées ne sont donc
            # jamais renvoyées.
            # =================================================
            for alert in created_alerts:
                recipient = (
                    recipients_by_id.get(
                        alert.recipient_user_id
                    )
                )

                if recipient is None:
                    # L'alerte pending est déjà commitée.
                    # Une erreur ici ne la perd donc pas.
                    raise RuntimeError(
                        "Alert recipient is not part "
                        "of the active security "
                        "responsible recipients"
                    )

                exposure_id = (
                    alert.vulnerability_exposure_id
                )

                if exposure_id is None:
                    raise RuntimeError(
                        "New vulnerability alert must "
                        "reference an exposure"
                    )

                notification = (
                    AlertNotification(
                        alert_id=alert.id,
                        organization_id=(
                            alert.organization_id
                        ),
                        machine_id=(
                            alert.machine_id
                        ),
                        vulnerability_exposure_id=(
                            exposure_id
                        ),
                        canonical_vulnerability_id=(
                            alert
                            .canonical_vulnerability_id
                        ),
                        alert_type=(
                            alert.alert_type
                        ),
                        recipient_user_id=(
                            recipient.id
                        ),
                        recipient_email=(
                            recipient.email
                        ),
                        recipient_display_name=(
                            recipient.display_name
                        ),
                    )
                )

                try:
                    self._notification_port.send(
                        notification
                    )

                except NotificationDeliveryError:
                    failed_alert_ids.append(
                        alert.id
                    )

                else:
                    sent_updates.append(
                        AlertSentUpdate(
                            alert_id=alert.id,

                            # Pour V1, l'évaluation et la
                            # notification appartiennent au même
                            # cycle. On conserve donc le timestamp
                            # déterministe fourni au service.
                            sent_at=evaluated_at,
                        )
                    )

            # =================================================
            # PHASE 3
            #
            # Une seule écriture batch par statut.
            # =================================================
            if sent_updates:
                unit_of_work.alerts.mark_sent_many(
                    organization_id=(
                        organization_id
                    ),
                    updates=tuple(
                        sent_updates
                    ),
                )

            if failed_alert_ids:
                unit_of_work.alerts.mark_failed_many(
                    organization_id=(
                        organization_id
                    ),
                    alert_ids=tuple(
                        failed_alert_ids
                    ),
                )

            unit_of_work.commit()

            return AlertEvaluationResult(
                transition_count=len(
                    normalized_transitions
                ),
                recipient_count=len(
                    recipients
                ),
                candidate_event_count=(
                    candidate_event_count
                ),
                attempted_alert_count=len(
                    pending_alerts
                ),
                created_alerts=(
                    created_alerts
                ),
                sent_notification_count=len(
                    sent_updates
                ),
                failed_notification_count=len(
                    failed_alert_ids
                ),
            )

    @staticmethod
    def _normalize_transitions(
        values: Iterable[
            ExposureAlertTransition
        ],
    ) -> tuple[
        ExposureAlertTransition,
        ...,
    ]:
        if isinstance(
            values,
            (str, bytes),
        ):
            raise TypeError(
                "transitions must be iterable"
            )

        try:
            iterator = iter(
                values
            )

        except TypeError as error:
            raise TypeError(
                "transitions must be iterable"
            ) from error

        result: list[
            ExposureAlertTransition
        ] = []

        seen: set[
            UUID
        ] = set()

        for transition in iterator:
            if not isinstance(
                transition,
                ExposureAlertTransition,
            ):
                raise TypeError(
                    "transitions must contain "
                    "ExposureAlertTransition"
                )

            if transition.exposure_id in seen:
                raise ValueError(
                    "Duplicate exposure transition"
                )

            seen.add(
                transition.exposure_id
            )

            result.append(
                transition
            )

        return tuple(
            result
        )