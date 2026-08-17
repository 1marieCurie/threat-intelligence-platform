from __future__ import annotations

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from application.ports.outbound.security_responsible_read_repository import (
    SecurityResponsibleReadRepository,
    SecurityResponsibleRecipient,
)
from infrastructure.persistence.models.assets import (
    UserAccountModel,
)


class SecurityResponsibleReadRepositoryError(
    RuntimeError
):
    pass


class SqlAlchemySecurityResponsibleReadRepository(
    SecurityResponsibleReadRepository
):
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

    def find_active_by_organization_id(
        self,
        *,
        organization_id: UUID,
    ) -> tuple[
        SecurityResponsibleRecipient,
        ...,
    ]:
        if not isinstance(
            organization_id,
            UUID,
        ):
            raise TypeError(
                "organization_id must be a UUID"
            )

        statement = (
            select(
                UserAccountModel.id,
                UserAccountModel.email,
                UserAccountModel.display_name,
            )
            .where(
                UserAccountModel.organization_id
                == organization_id,
                UserAccountModel.role
                == "security_responsible",
                UserAccountModel.is_active
                .is_(True),
            )
            .order_by(
                UserAccountModel.created_at,
                UserAccountModel.id,
            )
        )

        try:
            rows = (
                self._session
                .execute(statement)
                .tuples()
                .all()
            )

        except SQLAlchemyError as error:
            raise (
                SecurityResponsibleReadRepositoryError(
                    "Unable to read active "
                    "security responsible recipients"
                )
            ) from error

        return tuple(
            SecurityResponsibleRecipient(
                id=user_id,
                email=email,
                display_name=display_name,
            )
            for (
                user_id,
                email,
                display_name,
            ) in rows
        )