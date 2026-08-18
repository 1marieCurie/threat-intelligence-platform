from __future__ import annotations

from uuid import (
    UUID,
    uuid4,
)

from sqlalchemy import (
    select,
    update,
)
from sqlalchemy.dialects.postgresql import (
    insert,
)
from sqlalchemy.exc import (
    SQLAlchemyError,
)
from sqlalchemy.orm import Session

from application.ports.outbound.alert_repository import (
    AlertRepository,
    AlertSentUpdate,
    PendingAlertCreate,
)
from domain.alert import Alert
from infrastructure.persistence.models.assets import (
    AlertModel,
    MachineModel,
    SoftwareComponentModel,
    VulnerabilityExposureModel,
)


class AlertRepositoryError(
    RuntimeError
):
    pass


class SqlAlchemyAlertRepository(
    AlertRepository
):
    """
    Repository PostgreSQL des alertes.

    Garanties V1 :
    - insertion pending uniquement ;
    - déduplication PostgreSQL ;
    - validation tenant/machine/exposure/canonical
      avant toute insertion ;
    - aucune fuite cross-tenant.
    """

    def __init__(
        self,
        *,
        session: Session,
    ) -> None:
        if session is None:
            raise ValueError(
                "session must not be None"
            )

        self._session = session

    def insert_pending_many(
        self,
        *,
        alerts: tuple[
            PendingAlertCreate,
            ...,
        ],
    ) -> tuple[
        Alert,
        ...,
    ]:
        if not isinstance(
            alerts,
            tuple,
        ):
            raise TypeError(
                "alerts must be a tuple"
            )

        if not alerts:
            return ()

        unique_alerts: list[
            PendingAlertCreate
        ] = []

        seen_keys: set[
            tuple[
                UUID,
                str,
            ]
        ] = set()

        for alert in alerts:
            if not isinstance(
                alert,
                PendingAlertCreate,
            ):
                raise TypeError(
                    "alerts must contain "
                    "PendingAlertCreate"
                )

            logical_key = (
                alert.organization_id,
                alert.deduplication_key,
            )

            if logical_key in seen_keys:
                continue

            seen_keys.add(
                logical_key
            )

            unique_alerts.append(
                alert
            )

        if not unique_alerts:
            return ()

        try:
            # =================================================
            # Sécurité multi-tenant.
            #
            # Une alerte ne peut pointer que vers une exposition
            # appartenant réellement à :
            #
            # organization_id
            #   -> machine_id
            #       -> software_component
            #           -> vulnerability_exposure
            #
            # Et la canonical fournie doit être celle de
            # l'exposition.
            # =================================================
            self._validate_exposure_scope(
                alerts=tuple(
                    unique_alerts
                )
            )

            rows = [
                {
                    "id": uuid4(),
                    "organization_id": (
                        alert.organization_id
                    ),
                    "machine_id": (
                        alert.machine_id
                    ),
                    "vulnerability_exposure_id": (
                        alert.vulnerability_exposure_id
                    ),
                    "canonical_vulnerability_id": (
                        alert.canonical_vulnerability_id
                    ),
                    "alert_type": (
                        alert.alert_type
                    ),
                    "recipient_user_id": (
                        alert.recipient_user_id
                    ),
                    "status": "pending",
                    "deduplication_key": (
                        alert.deduplication_key
                    ),
                    "created_at": (
                        alert.created_at
                    ),
                    "sent_at": None,
                }
                for alert in unique_alerts
            ]

            statement = (
                insert(
                    AlertModel
                )
                .values(
                    rows
                )
                .on_conflict_do_nothing(
                    constraint=(
                        "alert_organization_"
                        "deduplication_key"
                    )
                )
                .returning(
                    AlertModel.id,
                    AlertModel.organization_id,
                    AlertModel.machine_id,
                    AlertModel.vulnerability_exposure_id,
                    AlertModel.canonical_vulnerability_id,
                    AlertModel.alert_type,
                    AlertModel.recipient_user_id,
                    AlertModel.status,
                    AlertModel.deduplication_key,
                    AlertModel.created_at,
                    AlertModel.sent_at,
                )
            )

            result = (
                self._session
                .execute(
                    statement
                )
                .tuples()
                .all()
            )

            self._session.flush()

        except AlertRepositoryError:
            raise

        except SQLAlchemyError as error:
            raise (
                AlertRepositoryError(
                    "Unable to persist "
                    "pending alerts"
                )
            ) from error

        return tuple(
            Alert(
                id=row[0],
                organization_id=row[1],
                machine_id=row[2],
                vulnerability_exposure_id=row[3],
                canonical_vulnerability_id=row[4],
                alert_type=row[5],
                recipient_user_id=row[6],
                status=row[7],
                deduplication_key=row[8],
                created_at=row[9],
                sent_at=row[10],
            )
            for row in result
        )

    def mark_sent_many(
        self,
        *,
        organization_id: UUID,
        updates: tuple[
            AlertSentUpdate,
            ...,
        ],
    ) -> int:
        if not isinstance(
            organization_id,
            UUID,
        ):
            raise TypeError(
                "organization_id must be a UUID"
            )

        if not isinstance(
            updates,
            tuple,
        ):
            raise TypeError(
                "updates must be a tuple"
            )

        if not updates:
            return 0

        sent_at_by_alert: dict[
            UUID,
            object,
        ] = {}

        for item in updates:
            if not isinstance(
                item,
                AlertSentUpdate,
            ):
                raise TypeError(
                    "updates must contain "
                    "AlertSentUpdate"
                )

            existing = (
                sent_at_by_alert.get(
                    item.alert_id
                )
            )

            if (
                item.alert_id
                in sent_at_by_alert
                and existing != item.sent_at
            ):
                raise ValueError(
                    "Conflicting sent_at values "
                    "for the same alert"
                )

            sent_at_by_alert[
                item.alert_id
            ] = item.sent_at

        updated_count = 0

        try:
            for (
                alert_id,
                sent_at,
            ) in sent_at_by_alert.items():
                statement = (
                    update(
                        AlertModel
                    )
                    .where(
                        AlertModel.id
                        == alert_id,
                        AlertModel.organization_id
                        == organization_id,
                        AlertModel.status.in_(
                            (
                                "pending",
                                "failed",
                            )
                        ),
                    )
                    .values(
                        status="sent",
                        sent_at=sent_at,
                    )
                )

                result = (
                    self._session.execute(
                        statement
                    )
                )

                if result.rowcount is not None: # pyright: ignore[reportAttributeAccessIssue]
                    updated_count += (
                        result.rowcount # pyright: ignore[reportAttributeAccessIssue]
                    )

            self._session.flush()

        except SQLAlchemyError as error:
            raise AlertRepositoryError(
                "Unable to mark alerts as sent"
            ) from error

        return updated_count

    def mark_failed_many(
        self,
        *,
        organization_id: UUID,
        alert_ids: tuple[
            UUID,
            ...,
        ],
    ) -> int:
        if not isinstance(
            organization_id,
            UUID,
        ):
            raise TypeError(
                "organization_id must be a UUID"
            )

        if not isinstance(
            alert_ids,
            tuple,
        ):
            raise TypeError(
                "alert_ids must be a tuple"
            )

        if not alert_ids:
            return 0

        unique_ids: list[
            UUID
        ] = []

        seen: set[
            UUID
        ] = set()

        for alert_id in alert_ids:
            if not isinstance(
                alert_id,
                UUID,
            ):
                raise TypeError(
                    "alert_ids must contain UUID"
                )

            if alert_id in seen:
                continue

            seen.add(
                alert_id
            )

            unique_ids.append(
                alert_id
            )

        try:
            statement = (
                update(
                    AlertModel
                )
                .where(
                    AlertModel.organization_id
                    == organization_id,
                    AlertModel.id.in_(
                        tuple(
                            unique_ids
                        )
                    ),
                    # Une alerte déjà envoyée ne doit
                    # jamais être rétrogradée failed.
                    AlertModel.status
                    == "pending",
                )
                .values(
                    status="failed",
                    sent_at=None,
                )
            )

            result = (
                self._session.execute(
                    statement
                )
            )

            self._session.flush()

        except SQLAlchemyError as error:
            raise AlertRepositoryError(
                "Unable to mark alerts as failed"
            ) from error

        return (
            result.rowcount # pyright: ignore[reportAttributeAccessIssue]
            if result.rowcount is not None # pyright: ignore[reportAttributeAccessIssue]
            else 0
        )

    def _validate_exposure_scope(
        self,
        *,
        alerts: tuple[
            PendingAlertCreate,
            ...,
        ],
    ) -> None:
        requested_scope = {
            (
                alert.organization_id,
                alert.machine_id,
                alert.vulnerability_exposure_id,
                alert.canonical_vulnerability_id,
            )
            for alert in alerts
        }

        exposure_ids = tuple(
            {
                alert.vulnerability_exposure_id
                for alert in alerts
            }
        )

        statement = (
            select(
                MachineModel.organization_id,
                MachineModel.id,
                VulnerabilityExposureModel.id,
                VulnerabilityExposureModel
                .canonical_vulnerability_id,
            )
            .select_from(
                VulnerabilityExposureModel
            )
            .join(
                SoftwareComponentModel,
                SoftwareComponentModel.id
                == VulnerabilityExposureModel
                .software_component_id,
            )
            .join(
                MachineModel,
                MachineModel.id
                == SoftwareComponentModel
                .machine_id,
            )
            .where(
                VulnerabilityExposureModel.id
                .in_(
                    exposure_ids
                )
            )
        )

        persisted_scope = set(
            self._session
            .execute(
                statement
            )
            .tuples()
            .all()
        )

        missing_or_foreign = (
            requested_scope
            - persisted_scope
        )

        if missing_or_foreign:
            raise (
                AlertRepositoryError(
                    "Alert exposure does not belong "
                    "to the requested organization "
                    "and machine, or canonical "
                    "vulnerability does not match"
                )
            )