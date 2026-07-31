from __future__ import annotations

import re
from collections.abc import (
    Iterable,
    Iterator,
    Mapping,
)
from typing import Any

from sqlalchemy import (
    func,
    select,
)
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from application.models.epss_snapshot import (
    EPSSSnapshot,
)
from application.ports.outbound.epss_score_repository import (
    WritableEPSSScoreRepository,
)
from infrastructure.persistence.models.normalized import (
    EPSSScoreModel,
)


class SqlAlchemyEPSSScoreRepository(
    WritableEPSSScoreRepository
):
    """
    Repository PostgreSQL des derniers scores EPSS connus.

    Les lectures groupées utilisent une seule requête SQL.
    Les écritures utilisent un upsert PostgreSQL par lots.

    Un snapshot ancien ne peut pas remplacer un snapshot
    possédant une date plus récente.
    """

    CVE_ID_PATTERN = re.compile(
        r"^CVE-[0-9]{4}-[0-9]{4,}$",
        re.IGNORECASE,
    )

    UPSERT_BATCH_SIZE = 500

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

    def find_by_cve_id(
        self,
        cve_id: str,
    ) -> EPSSSnapshot | None:
        normalized_cve_id = self._normalize_cve_id(
            cve_id
        )

        statement = (
            select(
                EPSSScoreModel
            )
            .where(
                EPSSScoreModel.cve_id
                == normalized_cve_id
            )
            .limit(1)
        )

        model = (
            self._session
            .execute(statement)
            .scalar_one_or_none()
        )

        if model is None:
            return None

        return self._to_snapshot(
            model
        )

    def find_many_by_cve_ids(
        self,
        cve_ids: Iterable[str],
    ) -> dict[str, EPSSSnapshot]:
        normalized_cve_ids = (
            self._normalize_cve_ids(
                cve_ids
            )
        )

        if not normalized_cve_ids:
            return {}

        statement = (
            select(
                EPSSScoreModel
            )
            .where(
                EPSSScoreModel.cve_id.in_(
                    normalized_cve_ids
                )
            )
        )

        models = (
            self._session
            .execute(statement)
            .scalars()
            .all()
        )

        models_by_cve_id = {
            model.cve_id: model
            for model in models
        }

        return {
            cve_id: self._to_snapshot(
                models_by_cve_id[cve_id]
            )
            for cve_id in normalized_cve_ids
            if cve_id in models_by_cve_id
        }

    def upsert_many(
        self,
        snapshots_by_cve: Mapping[
            str,
            EPSSSnapshot,
        ],
    ) -> int:
        rows = self._prepare_rows(
            snapshots_by_cve
        )

        if not rows:
            return 0

        for batch in self._chunked(
            rows,
            self.UPSERT_BATCH_SIZE,
        ):
            statement = insert(
                EPSSScoreModel
            ).values(
                batch
            )

            excluded = statement.excluded

            statement = (
                statement.on_conflict_do_update(
                    index_elements=[
                        EPSSScoreModel.cve_id,
                    ],
                    set_={
                        "epss_score": (
                            excluded.epss_score
                        ),
                        "percentile": (
                            excluded.percentile
                        ),
                        "score_date": (
                            excluded.score_date
                        ),
                        "api_version": (
                            excluded.api_version
                        ),
                        "synchronized_at": (
                            func.now()
                        ),
                    },
                    where=(
                        excluded.score_date
                        >= EPSSScoreModel.score_date
                    ),
                )
            )

            self._session.execute(
                statement
            )

        self._session.flush()

        return len(rows)

    def _prepare_rows(
        self,
        snapshots_by_cve: Mapping[
            str,
            EPSSSnapshot,
        ],
    ) -> list[dict[str, Any]]:
        if not isinstance(
            snapshots_by_cve,
            Mapping,
        ):
            raise TypeError(
                "snapshots_by_cve must be a mapping"
            )

        rows_by_cve_id: dict[
            str,
            dict[str, Any],
        ] = {}

        for cve_id, snapshot in (
            snapshots_by_cve.items()
        ):
            if not isinstance(
                snapshot,
                EPSSSnapshot,
            ):
                raise TypeError(
                    "Every value must be "
                    "an EPSSSnapshot"
                )

            normalized_cve_id = (
                self._normalize_cve_id(
                    cve_id
                )
            )

            row = {
                "cve_id": normalized_cve_id,
                "epss_score": snapshot.score,
                "percentile": (
                    snapshot.percentile
                ),
                "score_date": (
                    snapshot.score_date
                ),
                "api_version": (
                    snapshot.api_version
                ),
            }

            existing_row = rows_by_cve_id.get(
                normalized_cve_id
            )

            if (
                existing_row is not None
                and existing_row != row
            ):
                raise ValueError(
                    "Conflicting duplicate EPSS "
                    f"snapshot: {normalized_cve_id}"
                )

            rows_by_cve_id.setdefault(
                normalized_cve_id,
                row,
            )

        return list(
            rows_by_cve_id.values()
        )

    @staticmethod
    def _to_snapshot(
        model: EPSSScoreModel,
    ) -> EPSSSnapshot:
        return EPSSSnapshot(
            score=model.epss_score,
            percentile=model.percentile,
            score_date=model.score_date,
            api_version=model.api_version,
        )

    @classmethod
    def _normalize_cve_id(
        cls,
        value: str,
    ) -> str:
        if not isinstance(
            value,
            str,
        ):
            raise TypeError(
                "cve_id must be a string"
            )

        normalized_value = (
            value.strip().upper()
        )

        if (
            len(normalized_value) > 32
            or cls.CVE_ID_PATTERN.fullmatch(
                normalized_value
            )
            is None
        ):
            raise ValueError(
                "cve_id must be a valid "
                "CVE identifier"
            )

        return normalized_value

    @classmethod
    def _normalize_cve_ids(
        cls,
        values: Iterable[str],
    ) -> list[str]:
        if isinstance(
            values,
            (str, bytes),
        ):
            raise TypeError(
                "cve_ids must be an iterable "
                "of strings"
            )

        try:
            provided_values = list(
                values
            )
        except TypeError as error:
            raise TypeError(
                "cve_ids must be an iterable "
                "of strings"
            ) from error

        normalized_values = [
            cls._normalize_cve_id(
                value
            )
            for value in provided_values
        ]

        return list(
            dict.fromkeys(
                normalized_values
            )
        )

    @staticmethod
    def _chunked(
        values: list[dict[str, Any]],
        size: int,
    ) -> Iterator[list[dict[str, Any]]]:
        for index in range(
            0,
            len(values),
            size,
        ):
            yield values[
                index:index + size
            ]