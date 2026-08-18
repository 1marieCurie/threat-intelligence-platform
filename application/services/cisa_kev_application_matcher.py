from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from uuid import UUID

from application.ports.outbound.cisa_kev_application_read_repository import (
    CisaKevApplicationCandidate,
)
from domain.software_component import SoftwareComponent


@dataclass(
    frozen=True,
    slots=True,
)
class CisaKevApplicationMatch:
    software_component_id: UUID

    cve_id: str

    applicability_status: str

    match_rule: str
    match_version: str | None

    is_kev: bool


class CisaKevApplicationMatcher:
    """
    Matcher déterministe V1 entre une application
    Windows installée et les entrées CISA KEV.

    Règle :
    - vendor normalisé exact ;
    - product normalisé exact ;
    - aucune fuzzy matching ;
    - aucune décision basée sur la version.

    Important :
    CISA KEV indique qu'une vulnérabilité est
    exploitée dans la nature, mais ne démontre pas
    que la version installée localement est
    vulnérable.

    Un match CISA est donc `potential`,
    jamais `confirmed`.
    """

    MATCH_RULE = (
        "cisa_kev_exact_vendor_product_v1"
    )

    def match(
        self,
        *,
        component: SoftwareComponent,
        candidates: Iterable[
            CisaKevApplicationCandidate
        ],
    ) -> tuple[
        CisaKevApplicationMatch,
        ...,
    ]:
        self._validate_component(
            component
        )

        if isinstance(
            candidates,
            (str, bytes),
        ):
            raise TypeError(
                "candidates must be an iterable "
                "of CisaKevApplicationCandidate"
            )

        try:
            submitted_candidates = tuple(
                candidates
            )
        except TypeError as error:
            raise TypeError(
                "candidates must be iterable"
            ) from error

        matches_by_cve: dict[
            str,
            CisaKevApplicationMatch,
        ] = {}

        for candidate in submitted_candidates:
            if not isinstance(
                candidate,
                CisaKevApplicationCandidate,
            ):
                raise TypeError(
                    "Every candidate must be a "
                    "CisaKevApplicationCandidate"
                )

            if (
                candidate
                .normalized_vendor_project
                != component.normalized_vendor
            ):
                continue

            if (
                candidate.normalized_product
                != component.normalized_name
            ):
                continue

            cve_id = (
                candidate
                .cve_id
                .strip()
                .upper()
            )

            if not cve_id:
                raise ValueError(
                    "candidate cve_id must not "
                    "be empty"
                )

            matches_by_cve.setdefault(
                cve_id,
                CisaKevApplicationMatch(
                    software_component_id=(
                        component.id
                    ),
                    cve_id=cve_id,
                    applicability_status=(
                        "potential"
                    ),
                    match_rule=(
                        self.MATCH_RULE
                    ),
                    match_version=(
                        component.version
                    ),
                    is_kev=True,
                ),
            )

        return tuple(
            matches_by_cve[cve_id]
            for cve_id
            in sorted(
                matches_by_cve
            )
        )

    @staticmethod
    def _validate_component(
        component: SoftwareComponent,
    ) -> None:
        if not isinstance(
            component,
            SoftwareComponent,
        ):
            raise TypeError(
                "component must be a "
                "SoftwareComponent"
            )

        if (
            component.component_type
            != "application"
        ):
            raise ValueError(
                "component must be an application"
            )

        if (
            component.normalized_vendor
            is None
        ):
            raise ValueError(
                "application normalized_vendor "
                "is required"
            )

        if (
            component.normalized_name
            is None
        ):
            raise ValueError(
                "application normalized_name "
                "is required"
            )