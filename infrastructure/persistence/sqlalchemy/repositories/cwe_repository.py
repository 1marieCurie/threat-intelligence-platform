from __future__ import annotations

import re
from collections.abc import Iterable, Iterator
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from application.ports.outbound.cwe_repository import (
    WritableCWERepository,
)
from domain.cwe_weakness import CWEWeakness
from infrastructure.persistence.models.normalized import (
    CWEWeaknessModel,
)


class SqlAlchemyCWERepository(
    WritableCWERepository
):
    """
    Repository PostgreSQL du catalogue officiel CWE.

    Les écritures utilisent un upsert PostgreSQL par lots afin
    d'éviter une requête SELECT puis INSERT pour chaque faiblesse.
    """

    CWE_ID_PATTERN = re.compile(
        r"^(?:CWE-)?(\d+)$",
        re.IGNORECASE,
    )

    UPSERT_BATCH_SIZE = 100

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

    def find_by_id(
        self,
        cwe_id: str,
    ) -> CWEWeakness | None:
        normalized_id = self._normalize_cwe_id(
            cwe_id
        )

        statement = (
            select(
                CWEWeaknessModel
            )
            .where(
                CWEWeaknessModel.cwe_id
                == normalized_id
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

        return self._to_domain(
            model
        )

    def find_many_by_ids(
        self,
        cwe_ids: Iterable[str],
    ) -> list[CWEWeakness]:
        normalized_ids = (
            self._normalize_cwe_ids(
                cwe_ids
            )
        )

        if not normalized_ids:
            return []

        statement = (
            select(
                CWEWeaknessModel
            )
            .where(
                CWEWeaknessModel.cwe_id.in_(
                    normalized_ids
                )
            )
        )

        models = (
            self._session
            .execute(statement)
            .scalars()
            .all()
        )

        models_by_id = {
            model.cwe_id: model
            for model in models
        }

        return [
            self._to_domain(
                models_by_id[cwe_id]
            )
            for cwe_id in normalized_ids
            if cwe_id in models_by_id
        ]

    def upsert_many(
        self,
        weaknesses: Iterable[CWEWeakness],
    ) -> int:
        rows = self._prepare_rows(
            weaknesses
        )

        if not rows:
            return 0

        for batch in self._chunked(
            rows,
            self.UPSERT_BATCH_SIZE,
        ):
            statement = insert(
                CWEWeaknessModel
            ).values(
                batch
            )

            excluded = statement.excluded

            statement = (
                statement.on_conflict_do_update(
                    index_elements=[
                        CWEWeaknessModel.cwe_id,
                    ],
                    set_={
                        "name": excluded.name,
                        "description": (
                            excluded.description
                        ),
                        "abstraction": (
                            excluded.abstraction
                        ),
                        "structure": (
                            excluded.structure
                        ),
                        "status": excluded.status,
                        "extended_description": (
                            excluded
                            .extended_description
                        ),
                        "likelihood_of_exploit": (
                            excluded
                            .likelihood_of_exploit
                        ),
                        "mapping_usage": (
                            excluded.mapping_usage
                        ),
                        "mapping_rationale": (
                            excluded.mapping_rationale
                        ),
                        "relationships": (
                            excluded.relationships
                        ),
                        "consequences": (
                            excluded.consequences
                        ),
                        "mitigations": (
                            excluded.mitigations
                        ),
                        "detection_methods": (
                            excluded.detection_methods
                        ),
                        "applicable_platforms": (
                            excluded
                            .applicable_platforms
                        ),
                        "modes_of_introduction": (
                            excluded
                            .modes_of_introduction
                        ),
                        "alternate_terms": (
                            excluded.alternate_terms
                        ),
                        "related_capec_ids": (
                            excluded.related_capec_ids
                        ),
                        "catalog_version": (
                            excluded.catalog_version
                        ),
                        "catalog_date": (
                            excluded.catalog_date
                        ),
                        "synchronized_at": (
                            func.now()
                        ),
                    },
                )
            )

            self._session.execute(
                statement
            )

        self._session.flush()

        return len(rows)

    def _prepare_rows(
        self,
        weaknesses: Iterable[CWEWeakness],
    ) -> list[dict[str, Any]]:
        if isinstance(
            weaknesses,
            (str, bytes),
        ):
            raise TypeError(
                "weaknesses must be an iterable "
                "of CWEWeakness objects"
            )

        try:
            values = list(
                weaknesses
            )
        except TypeError as error:
            raise TypeError(
                "weaknesses must be an iterable "
                "of CWEWeakness objects"
            ) from error

        rows_by_id: dict[
            str,
            dict[str, Any],
        ] = {}

        for weakness in values:
            if not isinstance(
                weakness,
                CWEWeakness,
            ):
                raise TypeError(
                    "Every weakness must be "
                    "a CWEWeakness"
                )

            row = self._serialize(
                weakness
            )

            cwe_id = row["cwe_id"]

            existing = rows_by_id.get(
                cwe_id
            )

            if (
                existing is not None
                and existing != row
            ):
                raise ValueError(
                    "Conflicting duplicate CWE "
                    f"entry: {cwe_id}"
                )

            rows_by_id.setdefault(
                cwe_id,
                row,
            )

        return list(
            rows_by_id.values()
        )

    def _serialize(
        self,
        weakness: CWEWeakness,
    ) -> dict[str, Any]:
        return {
            "cwe_id": self._normalize_cwe_id(
                weakness.id
            ),
            "name": self._required_text(
                weakness.name,
                field_name="name",
            ),
            "description": self._required_text(
                weakness.description,
                field_name="description",
            ),
            "abstraction": self._optional_text(
                weakness.abstraction
            ),
            "structure": self._optional_text(
                weakness.structure
            ),
            "status": self._optional_text(
                weakness.status
            ),
            "extended_description": (
                self._optional_text(
                    weakness
                    .extended_description
                )
            ),
            "likelihood_of_exploit": (
                self._optional_text(
                    weakness
                    .likelihood_of_exploit
                )
            ),
            "mapping_usage": self._optional_text(
                weakness.mapping_usage
            ),
            "mapping_rationale": (
                self._optional_text(
                    weakness.mapping_rationale
                )
            ),
            "relationships": (
                self._json_collection(
                    weakness.relationships,
                    field_name="relationships",
                )
            ),
            "consequences": (
                self._json_collection(
                    weakness.consequences,
                    field_name="consequences",
                )
            ),
            "mitigations": (
                self._json_collection(
                    weakness.mitigations,
                    field_name="mitigations",
                )
            ),
            "detection_methods": (
                self._json_collection(
                    weakness.detection_methods,
                    field_name="detection_methods",
                )
            ),
            "applicable_platforms": (
                self._json_collection(
                    weakness
                    .applicable_platforms,
                    field_name=(
                        "applicable_platforms"
                    ),
                )
            ),
            "modes_of_introduction": (
                self._json_collection(
                    weakness
                    .modes_of_introduction,
                    field_name=(
                        "modes_of_introduction"
                    ),
                )
            ),
            "alternate_terms": (
                self._string_collection(
                    weakness.alternate_terms,
                    field_name="alternate_terms",
                )
            ),
            "related_capec_ids": (
                self._string_collection(
                    weakness.related_capec_ids,
                    field_name=(
                        "related_capec_ids"
                    ),
                )
            ),
            "catalog_version": (
                self._optional_text(
                    weakness.catalog_version
                )
            ),
            "catalog_date": self._optional_text(
                weakness.catalog_date
            ),
        }

    @staticmethod
    def _to_domain(
        model: CWEWeaknessModel,
    ) -> CWEWeakness:
        return CWEWeakness(
            id=model.cwe_id,
            name=model.name,
            description=model.description,
            abstraction=model.abstraction,
            structure=model.structure,
            status=model.status,
            extended_description=(
                model.extended_description
            ),
            likelihood_of_exploit=(
                model.likelihood_of_exploit
            ),
            mapping_usage=model.mapping_usage,
            mapping_rationale=(
                model.mapping_rationale
            ),
            relationships=tuple(
                dict(item)
                for item in model.relationships
            ),
            consequences=tuple(
                dict(item)
                for item in model.consequences
            ),
            mitigations=tuple(
                dict(item)
                for item in model.mitigations
            ),
            detection_methods=tuple(
                dict(item)
                for item in model.detection_methods
            ),
            applicable_platforms=tuple(
                dict(item)
                for item
                in model.applicable_platforms
            ),
            modes_of_introduction=tuple(
                dict(item)
                for item
                in model.modes_of_introduction
            ),
            alternate_terms=tuple(
                model.alternate_terms
            ),
            related_capec_ids=tuple(
                model.related_capec_ids
            ),
            catalog_version=(
                model.catalog_version
            ),
            catalog_date=model.catalog_date,
        )

    @classmethod
    def _normalize_cwe_id(
        cls,
        value: str,
    ) -> str:
        if not isinstance(
            value,
            str,
        ):
            raise TypeError(
                "cwe_id must be a string"
            )

        normalized = value.strip()

        match = cls.CWE_ID_PATTERN.fullmatch(
            normalized
        )

        if match is None:
            raise ValueError(
                "cwe_id must be a valid CWE identifier"
            )

        numeric_id = int(
            match.group(1)
        )

        if numeric_id < 1:
            raise ValueError(
                "cwe_id must be a valid CWE identifier"
            )

        return f"CWE-{numeric_id}"

    @classmethod
    def _normalize_cwe_ids(
        cls,
        values: Iterable[str],
    ) -> list[str]:
        if isinstance(
            values,
            (str, bytes),
        ):
            raise TypeError(
                "cwe_ids must be an iterable "
                "of strings"
            )

        try:
            normalized_values = [
                cls._normalize_cwe_id(
                    value
                )
                for value in values
            ]
        except TypeError as error:
            raise TypeError(
                "cwe_ids must be an iterable "
                "of strings"
            ) from error

        return list(
            dict.fromkeys(
                normalized_values
            )
        )

    @staticmethod
    def _required_text(
        value: str,
        *,
        field_name: str,
    ) -> str:
        if not isinstance(
            value,
            str,
        ):
            raise TypeError(
                f"{field_name} must be a string"
            )

        normalized = value.strip()

        if not normalized:
            raise ValueError(
                f"{field_name} must not be empty"
            )

        return normalized

    @staticmethod
    def _optional_text(
        value: str | None,
    ) -> str | None:
        if value is None:
            return None

        if not isinstance(
            value,
            str,
        ):
            raise TypeError(
                "optional text fields must "
                "contain strings or None"
            )

        normalized = value.strip()

        return normalized or None

    @staticmethod
    def _json_collection(
        values: Iterable[dict[str, Any]],
        *,
        field_name: str,
    ) -> list[dict[str, Any]]:
        normalized: list[
            dict[str, Any]
        ] = []

        for value in values:
            if not isinstance(
                value,
                dict,
            ):
                raise TypeError(
                    f"{field_name} must contain "
                    "dictionary values"
                )

            normalized.append(
                dict(value)
            )

        return normalized

    @staticmethod
    def _string_collection(
        values: Iterable[str],
        *,
        field_name: str,
    ) -> list[str]:
        normalized: list[str] = []

        for value in values:
            if not isinstance(
                value,
                str,
            ):
                raise TypeError(
                    f"{field_name} must contain "
                    "string values"
                )

            stripped = value.strip()

            if stripped:
                normalized.append(
                    stripped
                )

        return list(
            dict.fromkeys(
                normalized
            )
        )

    @staticmethod
    def _chunked(
        values: list[dict[str, Any]],
        size: int,
    ) -> Iterator[
        list[dict[str, Any]]
    ]:
        for start in range(
            0,
            len(values),
            size,
        ):
            yield values[
                start:start + size
            ]