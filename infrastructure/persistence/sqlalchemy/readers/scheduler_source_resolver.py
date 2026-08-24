from __future__ import annotations

from collections.abc import Callable
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from infrastructure.persistence.models.ops import (
    SourceModel,
)


SessionFactory = Callable[
    [],
    Session,
]


class SchedulerSourceResolutionError(
    RuntimeError
):
    pass


class SqlAlchemySchedulerSourceResolver:
    """
    Résout les UUID des sources nécessaires au scheduler.

    Les UUID ne sont jamais codés en dur.

    La source doit :
    - exister ;
    - avoir exactement le code demandé ;
    - être activée dans ops.source.
    """

    def __init__(
        self,
        *,
        session_factory: SessionFactory,
    ) -> None:
        if session_factory is None:
            raise ValueError(
                "session_factory must not be None"
            )

        if not callable(
            session_factory
        ):
            raise TypeError(
                "session_factory must be callable"
            )

        self._session_factory = (
            session_factory
        )

    def resolve_enabled_source_id(
        self,
        source_code: str,
    ) -> UUID:
        normalized_source_code = (
            self._normalize_source_code(
                source_code
            )
        )

        statement = (
            select(
                SourceModel.id,
                SourceModel.enabled,
            )
            .where(
                SourceModel.code
                == normalized_source_code
            )
            .limit(1)
        )

        try:
            with (
                self._session_factory()
                as session
            ):
                row = (
                    session.execute(
                        statement
                    )
                    .tuples()
                    .one_or_none()
                )

        except SQLAlchemyError as error:
            raise (
                SchedulerSourceResolutionError(
                    "Unable to resolve scheduler "
                    f"source {normalized_source_code}"
                )
            ) from error

        if row is None:
            raise (
                SchedulerSourceResolutionError(
                    "Required scheduler source "
                    f"{normalized_source_code} "
                    "does not exist"
                )
            )

        source_id = row[0]
        enabled = row[1]

        if not isinstance(
            source_id,
            UUID,
        ):
            raise (
                SchedulerSourceResolutionError(
                    "Scheduler source returned "
                    "an invalid UUID"
                )
            )

        if enabled is not True:
            raise (
                SchedulerSourceResolutionError(
                    "Required scheduler source "
                    f"{normalized_source_code} "
                    "is disabled"
                )
            )

        return source_id

    @staticmethod
    def _normalize_source_code(
        value: str,
    ) -> str:
        if not isinstance(
            value,
            str,
        ):
            raise TypeError(
                "source_code must be a string"
            )

        normalized = (
            value
            .strip()
            .upper()
        )

        if not normalized:
            raise ValueError(
                "source_code must not be empty"
            )

        if len(normalized) > 50:
            raise ValueError(
                "source_code is too long"
            )

        return normalized