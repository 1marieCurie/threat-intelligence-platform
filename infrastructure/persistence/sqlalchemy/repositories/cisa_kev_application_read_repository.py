from __future__ import annotations

import re
import unicodedata
from collections.abc import (
    Iterable,
    Sequence,
)

from sqlalchemy import (
    func,
    select,
    tuple_,
)
from sqlalchemy.exc import (
    SQLAlchemyError,
)
from sqlalchemy.orm import Session

from application.ports.outbound.cisa_kev_application_read_repository import (
    CisaKevApplicationCandidate,
    CisaKevApplicationKey,
)
from infrastructure.persistence.models.normalized import (
    CisaKevVulnerabilityModel,
)
from infrastructure.persistence.models.ops import (
    IngestionRunModel,
    SourceModel,
)
from infrastructure.persistence.models.raw import (
    IngestionRunPayloadModel,
)


class CisaKevApplicationReadRepositoryError(
    RuntimeError
):
    pass


class SqlAlchemyCisaKevApplicationReadRepository:
    """
    Reader des candidats CISA KEV pour les
    applications installées.

    Principes V1 :
    - dernier snapshot CISA_KEV completed uniquement ;
    - lookup batch vendor + product ;
    - comparaison stricte ;
    - aucune fuzzy matching ;
    - aucune création de vulnérabilité ;
    - aucune décision confirmed ici.
    """

    SOURCE_CODE = "CISA_KEV"

    LOOKUP_BATCH_SIZE = 200

    _WHITESPACE_PATTERN = re.compile(
        r"\s+"
    )

    def __init__(
        self,
        *,
        session: Session,
        source_code: str = SOURCE_CODE,
    ) -> None:
        if session is None:
            raise ValueError(
                "session must not be None"
            )

        if not isinstance(
            source_code,
            str,
        ):
            raise TypeError(
                "source_code must be a string"
            )

        normalized_source_code = (
            source_code.strip()
        )

        if not normalized_source_code:
            raise ValueError(
                "source_code must not be empty"
            )

        self._session = session
        self._source_code = (
            normalized_source_code
        )

    def find_candidates(
        self,
        *,
        application_keys: Iterable[
            CisaKevApplicationKey
        ],
    ) -> tuple[
        CisaKevApplicationCandidate,
        ...,
    ]:
        normalized_keys = (
            self._normalize_keys(
                application_keys
            )
        )

        if not normalized_keys:
            return ()

        candidates_by_identity: dict[
            tuple[str, str, str],
            CisaKevApplicationCandidate,
        ] = {}

        try:
            for batch in self._chunked(
                normalized_keys,
                self.LOOKUP_BATCH_SIZE,
            ):
                statement = (
                    self._build_statement(
                        batch
                    )
                )

                rows = (
                    self._session
                    .execute(statement)
                    .tuples()
                    .all()
                )

                requested_keys = set(
                    batch
                )

                for (
                    cve_id,
                    vendor_project,
                    product,
                ) in rows:
                    normalized_vendor = (
                        self._normalize_lookup_text(
                            vendor_project
                        )
                    )

                    normalized_product = (
                        self._normalize_lookup_text(
                            product
                        )
                    )

                    lookup_key = (
                        normalized_vendor,
                        normalized_product,
                    )

                    # Défense supplémentaire :
                    # la requête SQL sert à réduire le
                    # dataset, mais la validation finale
                    # reste déterministe en Python.
                    if (
                        lookup_key
                        not in requested_keys
                    ):
                        continue

                    candidate = (
                        CisaKevApplicationCandidate(
                            cve_id=(
                                cve_id
                                .strip()
                                .upper()
                            ),
                            vendor_project=(
                                vendor_project
                            ),
                            product=product,
                            normalized_vendor_project=(
                                normalized_vendor
                            ),
                            normalized_product=(
                                normalized_product
                            ),
                        )
                    )

                    identity = (
                        candidate.cve_id,
                        candidate
                        .normalized_vendor_project,
                        candidate
                        .normalized_product,
                    )

                    candidates_by_identity.setdefault(
                        identity,
                        candidate,
                    )

        except SQLAlchemyError as error:
            raise (
                CisaKevApplicationReadRepositoryError(
                    "Unable to read current "
                    "CISA KEV application candidates"
                )
            ) from error

        return tuple(
            candidates_by_identity[key]
            for key in sorted(
                candidates_by_identity
            )
        )

    def _build_statement(
        self,
        application_keys: Sequence[
            tuple[str, str]
        ],
    ):
        latest_run_id = (
            select(
                IngestionRunModel.id
            )
            .join(
                SourceModel,
                (
                    SourceModel.id
                    == IngestionRunModel
                    .source_id
                ),
            )
            .where(
                SourceModel.code
                == self._source_code,
                IngestionRunModel.status
                == "completed",
            )
            .order_by(
                IngestionRunModel
                .finished_at
                .desc()
                .nullslast(),
                IngestionRunModel
                .started_at
                .desc(),
                IngestionRunModel
                .id
                .desc(),
            )
            .limit(1)
            .scalar_subquery()
        )

        normalized_vendor_sql = (
            func.lower(
                func.regexp_replace(
                    func.btrim(
                        CisaKevVulnerabilityModel
                        .vendor_project
                    ),
                    "[[:space:]]+",
                    " ",
                    "g",
                )
            )
        )

        normalized_product_sql = (
            func.lower(
                func.regexp_replace(
                    func.btrim(
                        CisaKevVulnerabilityModel
                        .product
                    ),
                    "[[:space:]]+",
                    " ",
                    "g",
                )
            )
        )

        return (
            select(
                CisaKevVulnerabilityModel
                .cve_id,
                CisaKevVulnerabilityModel
                .vendor_project,
                CisaKevVulnerabilityModel
                .product,
            )
            .join(
                IngestionRunPayloadModel,
                (
                    IngestionRunPayloadModel
                    .raw_payload_id
                    == CisaKevVulnerabilityModel
                    .raw_payload_id
                ),
            )
            .where(
                IngestionRunPayloadModel
                .ingestion_run_id
                == latest_run_id,
                tuple_(
                    normalized_vendor_sql,
                    normalized_product_sql,
                ).in_(
                    application_keys
                ),
            )
            .order_by(
                CisaKevVulnerabilityModel
                .cve_id,
                CisaKevVulnerabilityModel
                .id,
            )
        )

    @classmethod
    def _normalize_keys(
        cls,
        application_keys: Iterable[
            CisaKevApplicationKey
        ],
    ) -> tuple[
        tuple[str, str],
        ...,
    ]:
        if isinstance(
            application_keys,
            (str, bytes),
        ):
            raise TypeError(
                "application_keys must be "
                "an iterable of "
                "CisaKevApplicationKey"
            )

        try:
            submitted = tuple(
                application_keys
            )
        except TypeError as error:
            raise TypeError(
                "application_keys must be iterable"
            ) from error

        normalized: set[
            tuple[str, str]
        ] = set()

        for key in submitted:
            if not isinstance(
                key,
                CisaKevApplicationKey,
            ):
                raise TypeError(
                    "Every application key must "
                    "be a CisaKevApplicationKey"
                )

            vendor = (
                cls._normalize_lookup_text(
                    key.vendor_project
                )
            )

            product = (
                cls._normalize_lookup_text(
                    key.product
                )
            )

            normalized.add(
                (
                    vendor,
                    product,
                )
            )

        return tuple(
            sorted(
                normalized
            )
        )

    @classmethod
    def _normalize_lookup_text(
        cls,
        value: str,
    ) -> str:
        if not isinstance(
            value,
            str,
        ):
            raise TypeError(
                "lookup value must be a string"
            )

        normalized = unicodedata.normalize(
            "NFKC",
            value,
        )

        normalized = (
            cls._WHITESPACE_PATTERN
            .sub(
                " ",
                normalized.strip(),
            )
            .lower()
        )

        if not normalized:
            raise ValueError(
                "lookup value must not be empty"
            )

        return normalized

    @staticmethod
    def _chunked(
        values: Sequence[
            tuple[str, str]
        ],
        size: int,
    ):
        for start in range(
            0,
            len(values),
            size,
        ):
            yield values[
                start:
                start + size
            ]