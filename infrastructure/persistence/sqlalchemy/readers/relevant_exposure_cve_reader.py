from __future__ import annotations

import re
from collections.abc import Callable

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from infrastructure.persistence.models.assets import (
    MachineModel,
    OrganizationModel,
    SoftwareComponentModel,
    VulnerabilityExposureModel,
)
from infrastructure.persistence.models.canonical import (
    CanonicalVulnerabilityIdentifierModel,
)


SessionFactory = Callable[
    [],
    Session,
]


class RelevantExposureCVEReaderError(
    RuntimeError
):
    pass


class SqlAlchemyRelevantExposureCVEReader:
    """
    Fournit au refresh EPSS uniquement les CVE actuellement
    pertinentes pour les actifs de la plateforme.

    Une CVE est sélectionnée lorsqu'elle appartient à une
    vulnérabilité canonique déjà exposée sur une machine
    d'une organisation active.

    Pagination keyset :
        CVE-...
            ↓
        CVE suivante

    Aucun OFFSET.
    """

    CVE_PATTERN = re.compile(
        r"^CVE-[0-9]{4}-[0-9]{4,19}$"
    )

    MAX_LIMIT = 1_000

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

    def read_batch(
        self,
        *,
        after_cve_id: str | None,
        limit: int,
    ) -> tuple[
        str,
        ...,
    ]:
        normalized_after = (
            self._normalize_optional_cve_id(
                after_cve_id
            )
        )

        normalized_limit = (
            self._validate_limit(
                limit
            )
        )

        statement = (
            select(
                CanonicalVulnerabilityIdentifierModel
                .value
            )
            .select_from(
                CanonicalVulnerabilityIdentifierModel
            )
            .join(
                VulnerabilityExposureModel,
                (
                    VulnerabilityExposureModel
                    .canonical_vulnerability_id
                    == (
                        CanonicalVulnerabilityIdentifierModel
                        .vulnerability_id
                    )
                ),
            )
            .join(
                SoftwareComponentModel,
                (
                    SoftwareComponentModel.id
                    == (
                        VulnerabilityExposureModel
                        .software_component_id
                    )
                ),
            )
            .join(
                MachineModel,
                (
                    MachineModel.id
                    == (
                        SoftwareComponentModel
                        .machine_id
                    )
                ),
            )
            .join(
                OrganizationModel,
                (
                    OrganizationModel.id
                    == (
                        MachineModel
                        .organization_id
                    )
                ),
            )
            .where(
                (
                    CanonicalVulnerabilityIdentifierModel
                    .namespace
                    == "CVE"
                ),
                OrganizationModel
                .is_active
                .is_(True),
            )
            .distinct()
        )

        if normalized_after is not None:
            statement = (
                statement
                .where(
                    (
                        CanonicalVulnerabilityIdentifierModel
                        .value
                    )
                    > normalized_after
                )
            )

        statement = (
            statement
            .order_by(
                (
                    CanonicalVulnerabilityIdentifierModel
                    .value
                    .asc()
                )
            )
            .limit(
                normalized_limit
            )
        )

        try:
            with (
                self._session_factory()
                as session
            ):
                values = (
                    session.execute(
                        statement
                    )
                    .scalars()
                    .all()
                )

        except SQLAlchemyError as error:
            raise (
                RelevantExposureCVEReaderError(
                    "Unable to read relevant "
                    "exposure CVEs"
                )
            ) from error

        result = tuple(
            values
        )

        self._validate_result(
            result
        )

        return result

    @classmethod
    def _normalize_optional_cve_id(
        cls,
        value: str | None,
    ) -> str | None:
        if value is None:
            return None

        if not isinstance(
            value,
            str,
        ):
            raise TypeError(
                "after_cve_id must be "
                "a string or None"
            )

        normalized = (
            value
            .strip()
            .upper()
        )

        if (
            cls.CVE_PATTERN.fullmatch(
                normalized
            )
            is None
        ):
            raise ValueError(
                "after_cve_id must be "
                "a valid CVE identifier"
            )

        return normalized

    @classmethod
    def _validate_limit(
        cls,
        value: int,
    ) -> int:
        if (
            isinstance(
                value,
                bool,
            )
            or not isinstance(
                value,
                int,
            )
        ):
            raise TypeError(
                "limit must be an integer"
            )

        if not (
            1
            <= value
            <= cls.MAX_LIMIT
        ):
            raise ValueError(
                "limit must be between "
                f"1 and {cls.MAX_LIMIT}"
            )

        return value

    @classmethod
    def _validate_result(
        cls,
        values: tuple[
            str,
            ...,
        ],
    ) -> None:
        previous: str | None = None

        for value in values:
            if not isinstance(
                value,
                str,
            ):
                raise RuntimeError(
                    "Relevant CVE query returned "
                    "a non-string value"
                )

            if (
                cls.CVE_PATTERN.fullmatch(
                    value
                )
                is None
            ):
                raise RuntimeError(
                    "Relevant CVE query returned "
                    "an invalid identifier"
                )

            if (
                previous is not None
                and value <= previous
            ):
                raise RuntimeError(
                    "Relevant CVE query returned "
                    "a non-ordered result"
                )

            previous = value