from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import (
    datetime,
    timezone,
)
from uuid import UUID

from application.ports.outbound.cisa_kev_application_read_repository import (
    CisaKevApplicationCandidate,
    CisaKevApplicationKey,
)
from application.ports.outbound.vulnerability_exposure_repository import (
    VulnerabilityExposureDetection,
)
from application.ports.outbound.vulnerability_exposure_unit_of_work import (
    VulnerabilityExposureUnitOfWork,
)
from application.services.cisa_kev_application_matcher import (
    CisaKevApplicationMatcher,
)
from application.services.cisa_kev_canonical_match_resolver import (
    CisaKevCanonicalMatchResolver,
    ResolvedCisaKevApplicationMatch,
)
from domain.software_component import (
    SoftwareComponent,
)


@dataclass(
    frozen=True,
    slots=True,
)
class CisaKevApplicationReconciliationResult:
    application_count: int
    eligible_application_count: int

    candidate_count: int
    match_count: int

    resolved_match_count: int
    unresolved_match_count: int

    upserted_exposure_count: int
    preserved_foreign_exposure_count: int

    kev_enriched_exposure_count: int
    deleted_exposure_count: int


class ReconcileCisaKevApplicationExposuresService:
    """
    Réconcilie les applications d'une machine avec
    le snapshot CISA KEV courant.

    Responsabilités V1 :
    - applications uniquement ;
    - vendor + produit normalisés exacts ;
    - résolution CVE -> CanonicalVulnerability ;
    - exposition CISA = potential ;
    - is_kev enrichi séparément ;
    - suppression ciblée des anciennes expositions
      appartenant à la règle CISA ;
    - aucune dégradation d'une exposition possédée
      par une autre règle de matching.
    """

    def __init__(
        self,
        *,
        unit_of_work: VulnerabilityExposureUnitOfWork,
        matcher: CisaKevApplicationMatcher | None = None,
    ) -> None:
        if unit_of_work is None:
            raise ValueError(
                "unit_of_work must not be None"
            )

        self._unit_of_work = unit_of_work

        self._matcher = (
            matcher
            or CisaKevApplicationMatcher()
        )

    def reconcile(
        self,
        *,
        organization_id: UUID,
        machine_id: UUID,
        components: Sequence[
            SoftwareComponent
        ],
        evaluated_at: datetime,
    ) -> CisaKevApplicationReconciliationResult:
        normalized_organization_id = (
            self._validate_uuid(
                organization_id,
                field_name="organization_id",
            )
        )

        normalized_machine_id = (
            self._validate_uuid(
                machine_id,
                field_name="machine_id",
            )
        )

        normalized_evaluated_at = (
            self._normalize_datetime(
                evaluated_at,
                field_name="evaluated_at",
            )
        )

        applications = self._applications(
            components=components,
            machine_id=normalized_machine_id,
        )

        # Si aucune application n'existe plus sur la
        # machine, les SoftwareComponent supprimés par
        # la réconciliation d'inventaire ont déjà fait
        # disparaître leurs exposures via ON DELETE CASCADE.
        if not applications:
            return (
                CisaKevApplicationReconciliationResult(
                    application_count=0,
                    eligible_application_count=0,
                    candidate_count=0,
                    match_count=0,
                    resolved_match_count=0,
                    unresolved_match_count=0,
                    upserted_exposure_count=0,
                    preserved_foreign_exposure_count=0,
                    kev_enriched_exposure_count=0,
                    deleted_exposure_count=0,
                )
            )

        eligible_applications = tuple(
            application
            for application in applications
            if (
                application.normalized_vendor
                is not None
                and application.normalized_name
                is not None
            )
        )

        application_ids = tuple(
            application.id
            for application in applications
        )

        application_keys = (
            self._application_keys(
                eligible_applications
            )
        )

        with self._unit_of_work as unit_of_work:
            if application_keys:
                candidates = (
                    unit_of_work
                    .cisa_kev_applications
                    .find_candidates(
                        application_keys=(
                            application_keys
                        )
                    )
                )
            else:
                candidates = ()

            candidates_by_key = (
                self._group_candidates(
                    candidates
                )
            )

            matches = self._match_applications(
                applications=(
                    eligible_applications
                ),
                candidates_by_key=(
                    candidates_by_key
                ),
            )

            resolver = (
                CisaKevCanonicalMatchResolver(
                    canonical_vulnerability_repository=(
                        unit_of_work
                        .canonical_vulnerabilities
                    )
                )
            )

            resolution = resolver.resolve(
                matches=matches
            )

            # On charge toutes les expositions courantes
            # des applications, pas uniquement celles CISA.
            #
            # Cela permet d'éviter d'écraser une exposition
            # confirmed appartenant à une autre source.
            existing_exposures = (
                unit_of_work
                .vulnerability_exposures
                .list_for_components(
                    organization_id=(
                        normalized_organization_id
                    ),
                    machine_id=(
                        normalized_machine_id
                    ),
                    component_ids=(
                        application_ids
                    ),
                    match_rules=None,
                )
            )

            existing_by_key = {
                (
                    exposure.software_component_id,
                    exposure.canonical_vulnerability_id,
                ): exposure
                for exposure in existing_exposures
            }

            desired_keys = {
                (
                    resolved.match
                    .software_component_id,
                    resolved
                    .canonical_vulnerability_id,
                )
                for resolved
                in resolution.resolved
            }

            # Si le canonical ne peut pas être résolu
            # temporairement, on évite de supprimer les
            # expositions CISA du composant concerné.
            unresolved_component_ids = {
                match.software_component_id
                for match
                in resolution.unresolved
            }

            detections: list[
                VulnerabilityExposureDetection
            ] = []

            preserved_foreign_exposure_ids: list[
                UUID
            ] = []

            for resolved in resolution.resolved:
                key = (
                    resolved.match
                    .software_component_id,
                    resolved
                    .canonical_vulnerability_id,
                )

                existing = (
                    existing_by_key.get(
                        key
                    )
                )

                if (
                    existing is not None
                    and existing.match_rule
                    != self._matcher.MATCH_RULE
                ):
                    # Une autre règle possède déjà
                    # cette exposition.
                    #
                    # CISA ne modifie ni son
                    # applicability_status, ni son
                    # match_rule, ni sa severity.
                    #
                    # Elle est uniquement enrichie KEV.
                    preserved_foreign_exposure_ids.append(
                        existing.id
                    )

                    continue

                detections.append(
                    self._to_detection(
                        resolved=resolved,
                        evaluated_at=(
                            normalized_evaluated_at
                        ),
                    )
                )

            if detections:
                upserted_exposures = (
                    unit_of_work
                    .vulnerability_exposures
                    .upsert_detected_many(
                        organization_id=(
                            normalized_organization_id
                        ),
                        machine_id=(
                            normalized_machine_id
                        ),
                        detections=tuple(
                            detections
                        ),
                    )
                )
            else:
                upserted_exposures = ()

            # -------------------------------------------------
            # Enrichissement KEV
            # -------------------------------------------------
            #
            # Deux catégories sont enrichies :
            #
            # 1. les expositions CISA créées / actualisées ;
            # 2. les expositions d'une autre source qui
            #    correspondent à une CVE actuellement KEV.
            #
            # Exemple catégorie 2 :
            #
            # confirmed par une future source d'applicabilité
            # + CISA retrouve la même CVE
            # => on préserve confirmed et on met is_kev=True.
            kev_exposure_ids = self._deduplicate_uuids(
                (
                    *(
                        exposure.id
                        for exposure
                        in upserted_exposures
                    ),
                    *preserved_foreign_exposure_ids,
                )
            )

            if kev_exposure_ids:
                kev_enriched_count = (
                    unit_of_work
                    .vulnerability_exposures
                    .set_kev_status_many(
                        organization_id=(
                            normalized_organization_id
                        ),
                        machine_id=(
                            normalized_machine_id
                        ),
                        exposure_ids=(
                            kev_exposure_ids
                        ),
                        is_kev=True,
                    )
                )
            else:
                kev_enriched_count = 0

            # -------------------------------------------------
            # Suppression ciblée
            # -------------------------------------------------
            #
            # On supprime uniquement les anciennes expositions
            # appartenant à NOTRE règle CISA.
            #
            # Une exposition d'une autre règle ne nous
            # appartient pas et ne doit jamais être supprimée.
            stale_exposure_ids = tuple(
                exposure.id
                for exposure
                in existing_exposures
                if (
                    exposure.match_rule
                    == self._matcher.MATCH_RULE
                    and (
                        exposure.software_component_id
                        not in unresolved_component_ids
                    )
                    and (
                        (
                            exposure.software_component_id,
                            exposure.canonical_vulnerability_id,
                        )
                        not in desired_keys
                    )
                )
            )

            if stale_exposure_ids:
                deleted_count = (
                    unit_of_work
                    .vulnerability_exposures
                    .delete_by_ids(
                        organization_id=(
                            normalized_organization_id
                        ),
                        machine_id=(
                            normalized_machine_id
                        ),
                        exposure_ids=(
                            stale_exposure_ids
                        ),
                    )
                )
            else:
                deleted_count = 0

            unit_of_work.commit()

        return (
            CisaKevApplicationReconciliationResult(
                application_count=len(
                    applications
                ),
                eligible_application_count=len(
                    eligible_applications
                ),
                candidate_count=len(
                    candidates
                ),
                match_count=len(
                    matches
                ),
                resolved_match_count=len(
                    resolution.resolved
                ),
                unresolved_match_count=len(
                    resolution.unresolved
                ),
                upserted_exposure_count=len(
                    upserted_exposures
                ),
                preserved_foreign_exposure_count=(
                    len(
                        preserved_foreign_exposure_ids
                    )
                ),
                kev_enriched_exposure_count=(
                    kev_enriched_count
                ),
                deleted_exposure_count=(
                    deleted_count
                ),
            )
        )

    def _match_applications(
        self,
        *,
        applications: Sequence[
            SoftwareComponent
        ],
        candidates_by_key: dict[
            tuple[str, str],
            tuple[
                CisaKevApplicationCandidate,
                ...,
            ],
        ],
    ):
        matches = []

        for application in applications:
            normalized_vendor = (
                application.normalized_vendor
            )

            normalized_name = (
                application.normalized_name
            )

            if (
                normalized_vendor is None
                or normalized_name is None
            ):
                continue

            application_candidates = (
                candidates_by_key.get(
                    (
                        normalized_vendor,
                        normalized_name,
                    ),
                    (),
                )
            )

            matches.extend(
                self._matcher.match(
                    component=application,
                    candidates=(
                        application_candidates
                    ),
                )
            )

        return tuple(
            matches
        )

    @staticmethod
    def _group_candidates(
        candidates: Sequence[
            CisaKevApplicationCandidate
        ],
    ) -> dict[
        tuple[str, str],
        tuple[
            CisaKevApplicationCandidate,
            ...,
        ],
    ]:
        grouped: dict[
            tuple[str, str],
            list[
                CisaKevApplicationCandidate
            ],
        ] = {}

        for candidate in candidates:
            key = (
                candidate.normalized_vendor_project,
                candidate.normalized_product,
            )

            grouped.setdefault(
                key,
                [],
            ).append(
                candidate
            )

        return {
            key: tuple(values)
            for key, values
            in grouped.items()
        }

    @staticmethod
    def _application_keys(
        applications: Sequence[
            SoftwareComponent
        ],
    ) -> tuple[
        CisaKevApplicationKey,
        ...,
    ]:
        keys = {
            (
                application.normalized_vendor,
                application.normalized_name,
            )
            for application
            in applications
            if (
                application.normalized_vendor
                is not None
                and application.normalized_name
                is not None
            )
        }

        return tuple(
            CisaKevApplicationKey(
                vendor_project=vendor,
                product=product,
            )
            for vendor, product
            in sorted(
                keys
            )
        )

    @staticmethod
    def _applications(
        *,
        components: Sequence[
            SoftwareComponent
        ],
        machine_id: UUID,
    ) -> tuple[
        SoftwareComponent,
        ...,
    ]:
        if isinstance(
            components,
            (str, bytes),
        ):
            raise TypeError(
                "components must be a sequence "
                "of SoftwareComponent"
            )

        applications: list[
            SoftwareComponent
        ] = []

        for component in components:
            if not isinstance(
                component,
                SoftwareComponent,
            ):
                raise TypeError(
                    "Every component must be "
                    "a SoftwareComponent"
                )

            if (
                component.machine_id
                != machine_id
            ):
                raise ValueError(
                    "Software component machine "
                    "scope mismatch"
                )

            if (
                component.component_type
                != "application"
            ):
                continue

            applications.append(
                component
            )

        return tuple(
            sorted(
                applications,
                key=lambda component: (
                    component.normalized_vendor
                    or "",
                    component.normalized_name
                    or "",
                    str(component.id),
                ),
            )
        )

    @staticmethod
    def _to_detection(
        *,
        resolved: (
            ResolvedCisaKevApplicationMatch
        ),
        evaluated_at: datetime,
    ) -> VulnerabilityExposureDetection:
        match = resolved.match

        return (
            VulnerabilityExposureDetection(
                software_component_id=(
                    match.software_component_id
                ),
                canonical_vulnerability_id=(
                    resolved
                    .canonical_vulnerability_id
                ),
                applicability_status=(
                    "potential"
                ),
                match_rule=(
                    match.match_rule
                ),
                match_version=(
                    match.match_version
                ),

                # CISA KEV ne fournit pas une
                # severity propre à l'installation.
                #
                # La severity sera enrichie ensuite
                # via notre politique CVSS commune.
                severity=None,

                evaluated_at=(
                    evaluated_at
                ),
            )
        )

    @staticmethod
    def _deduplicate_uuids(
        values: Sequence[UUID],
    ) -> tuple[UUID, ...]:
        return tuple(
            dict.fromkeys(
                values
            )
        )

    @staticmethod
    def _validate_uuid(
        value: UUID,
        *,
        field_name: str,
    ) -> UUID:
        if not isinstance(
            value,
            UUID,
        ):
            raise TypeError(
                f"{field_name} must be a UUID"
            )

        if value.int == 0:
            raise ValueError(
                f"{field_name} must not be "
                "the nil UUID"
            )

        return value

    @staticmethod
    def _normalize_datetime(
        value: datetime,
        *,
        field_name: str,
    ) -> datetime:
        if not isinstance(
            value,
            datetime,
        ):
            raise TypeError(
                f"{field_name} must be "
                "a datetime"
            )

        if (
            value.tzinfo is None
            or value.utcoffset() is None
        ):
            raise ValueError(
                f"{field_name} must be "
                "timezone-aware"
            )

        return value.astimezone(
            timezone.utc
        )