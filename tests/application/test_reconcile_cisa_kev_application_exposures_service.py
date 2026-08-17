from __future__ import annotations

from collections.abc import Iterable
from dataclasses import replace
from datetime import (
    datetime,
    timezone,
)
from uuid import (
    UUID,
    uuid4,
)

import pytest

from application.ports.outbound.cisa_kev_application_read_repository import (
    CisaKevApplicationCandidate,
    CisaKevApplicationKey,
)
from application.ports.outbound.github_advisory_package_read_repository import (
    GitHubAdvisoryPackageCandidate,
    GitHubAdvisoryPackageKey,
)
from application.ports.outbound.vulnerability_exposure_repository import (
    VulnerabilityExposureDetection,
)
from application.services.cisa_kev_application_matcher import (
    CisaKevApplicationMatcher,
)
from application.services.reconcile_cisa_kev_application_exposures_service import (
    ReconcileCisaKevApplicationExposuresService,
)
from domain.canonical_vulnerability import (
    CanonicalVulnerability,
)
from domain.software_component import (
    SoftwareComponent,
)
from domain.vulnerability_evidence import (
    VulnerabilityEvidence,
)
from domain.vulnerability_exposure import (
    VulnerabilityExposure,
)
from domain.vulnerability_identifier import (
    VulnerabilityIdentifier,
)


NOW = datetime(
    2026,
    8,
    17,
    14,
    0,
    tzinfo=timezone.utc,
)


class FakeCisaKevApplicationReadRepository:
    def __init__(
        self,
        *,
        candidates: Iterable[
            CisaKevApplicationCandidate
        ] = (),
    ) -> None:
        self.candidates = tuple(
            candidates
        )

        self.call_count = 0

        self.requested_keys: tuple[
            CisaKevApplicationKey,
            ...,
        ] = ()

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
        self.call_count += 1

        self.requested_keys = tuple(
            application_keys
        )

        return self.candidates


class FakeGitHubAdvisoryPackageReadRepository:
    """
    Présent uniquement pour satisfaire le contrat
    complet du VulnerabilityExposureUnitOfWork.

    Le service CISA ne doit jamais l'utiliser.
    """

    def find_candidates(
        self,
        *,
        package_keys: Iterable[
            GitHubAdvisoryPackageKey
        ],
    ) -> tuple[
        GitHubAdvisoryPackageCandidate,
        ...,
    ]:
        del package_keys

        raise AssertionError(
            "GitHub Advisory package reader "
            "must not be called by CISA reconciliation"
        )


class FakeCanonicalVulnerabilityRepository:
    def __init__(
        self,
        *,
        mapping: dict[
            tuple[str, str],
            CanonicalVulnerability,
        ]
        | None = None,
    ) -> None:
        self.mapping = (
            mapping or {}
        )

        self.call_count = 0

        self.requested_identifiers: tuple[
            VulnerabilityIdentifier,
            ...,
        ] = ()

    def find_by_id(
        self,
        vulnerability_id: UUID,
    ) -> CanonicalVulnerability | None:
        del vulnerability_id

        raise AssertionError(
            "find_by_id must not be called "
            "by CISA reconciliation"
        )

    def find_many_by_ids(
        self,
        vulnerability_ids: Iterable[
            UUID
        ],
    ) -> dict[
        UUID,
        CanonicalVulnerability,
    ]:
        del vulnerability_ids

        raise AssertionError(
            "find_many_by_ids must not be called "
            "by CISA reconciliation"
        )

    def find_many_by_identifiers(
        self,
        identifiers: Iterable[
            VulnerabilityIdentifier
        ],
    ) -> dict[
        tuple[str, str],
        CanonicalVulnerability,
    ]:
        self.call_count += 1

        self.requested_identifiers = tuple(
            identifiers
        )

        return {
            identifier.key: self.mapping[
                identifier.key
            ]
            for identifier
            in self.requested_identifiers
            if identifier.key
            in self.mapping
        }

    def find_many_by_evidences(
        self,
        evidences: Iterable[
            VulnerabilityEvidence
        ],
    ) -> dict[
        tuple[str, str],
        CanonicalVulnerability,
    ]:
        del evidences

        raise AssertionError(
            "find_many_by_evidences must not "
            "be called by CISA reconciliation"
        )

    def upsert_many(
        self,
        vulnerabilities: Iterable[
            CanonicalVulnerability
        ],
    ) -> int:
        del vulnerabilities

        raise AssertionError(
            "upsert_many must not be called "
            "by CISA reconciliation"
        )


class FakeVulnerabilityExposureRepository:
    def __init__(
        self,
        *,
        existing_exposures: Iterable[
            VulnerabilityExposure
        ] = (),
    ) -> None:
        self.exposures = list(
            existing_exposures
        )

        self.list_calls: list[
            dict[str, object]
        ] = []

        self.upsert_calls: list[
            dict[str, object]
        ] = []

        self.delete_calls: list[
            dict[str, object]
        ] = []

        self.set_kev_calls: list[
            dict[str, object]
        ] = []

    def list_for_components(
        self,
        *,
        organization_id: UUID,
        machine_id: UUID,
        component_ids: Iterable[UUID],
        match_rules: Iterable[str] | None = None,
    ) -> tuple[
        VulnerabilityExposure,
        ...,
    ]:
        component_ids_tuple = tuple(
            component_ids
        )

        match_rules_tuple = (
            None
            if match_rules is None
            else tuple(
                match_rules
            )
        )

        self.list_calls.append(
            {
                "organization_id": (
                    organization_id
                ),
                "machine_id": machine_id,
                "component_ids": (
                    component_ids_tuple
                ),
                "match_rules": (
                    match_rules_tuple
                ),
            }
        )

        component_id_set = set(
            component_ids_tuple
        )

        match_rule_set = (
            None
            if match_rules_tuple is None
            else set(
                match_rules_tuple
            )
        )

        return tuple(
            exposure
            for exposure
            in self.exposures
            if (
                exposure.software_component_id
                in component_id_set
                and (
                    match_rule_set is None
                    or exposure.match_rule
                    in match_rule_set
                )
            )
        )

    def upsert_detected_many(
        self,
        *,
        organization_id: UUID,
        machine_id: UUID,
        detections: Iterable[
            VulnerabilityExposureDetection
        ],
    ) -> tuple[
        VulnerabilityExposure,
        ...,
    ]:
        detections_tuple = tuple(
            detections
        )

        self.upsert_calls.append(
            {
                "organization_id": (
                    organization_id
                ),
                "machine_id": machine_id,
                "detections": (
                    detections_tuple
                ),
            }
        )

        results: list[
            VulnerabilityExposure
        ] = []

        for detection in detections_tuple:
            existing = next(
                (
                    exposure
                    for exposure
                    in self.exposures
                    if (
                        exposure.software_component_id
                        == detection.software_component_id
                        and exposure
                        .canonical_vulnerability_id
                        == detection
                        .canonical_vulnerability_id
                    )
                ),
                None,
            )

            if existing is None:
                exposure = (
                    VulnerabilityExposure(
                        id=uuid4(),
                        software_component_id=(
                            detection
                            .software_component_id
                        ),
                        canonical_vulnerability_id=(
                            detection
                            .canonical_vulnerability_id
                        ),
                        applicability_status=(
                            detection
                            .applicability_status
                        ),
                        match_rule=(
                            detection.match_rule
                        ),
                        match_version=(
                            detection.match_version
                        ),
                        severity=(
                            detection.severity
                        ),
                        priority=None,
                        is_kev=False,
                        first_detected_at=(
                            detection.evaluated_at
                        ),
                        last_evaluated_at=(
                            detection.evaluated_at
                        ),
                    )
                )

                self.exposures.append(
                    exposure
                )

            else:
                exposure = (
                    VulnerabilityExposure(
                        id=existing.id,
                        software_component_id=(
                            existing
                            .software_component_id
                        ),
                        canonical_vulnerability_id=(
                            existing
                            .canonical_vulnerability_id
                        ),
                        applicability_status=(
                            detection
                            .applicability_status
                        ),
                        match_rule=(
                            detection.match_rule
                        ),
                        match_version=(
                            detection.match_version
                        ),
                        severity=(
                            detection.severity
                        ),
                        priority=(
                            existing.priority
                        ),
                        is_kev=(
                            existing.is_kev
                        ),
                        first_detected_at=(
                            existing
                            .first_detected_at
                        ),
                        last_evaluated_at=(
                            detection.evaluated_at
                        ),
                    )
                )

                self.exposures[
                    self.exposures.index(
                        existing
                    )
                ] = exposure

            results.append(
                exposure
            )

        return tuple(
            results
        )

    def set_kev_status_many(
        self,
        *,
        organization_id: UUID,
        machine_id: UUID,
        exposure_ids: Iterable[UUID],
        is_kev: bool,
    ) -> int:
        ids = tuple(
            dict.fromkeys(
                exposure_ids
            )
        )

        self.set_kev_calls.append(
            {
                "organization_id": (
                    organization_id
                ),
                "machine_id": machine_id,
                "exposure_ids": ids,
                "is_kev": is_kev,
            }
        )

        ids_set = set(
            ids
        )

        updated = 0

        for index, exposure in enumerate(
            self.exposures
        ):
            if exposure.id not in ids_set:
                continue

            self.exposures[index] = replace(
                exposure,
                is_kev=is_kev,
            )

            updated += 1

        return updated

    def delete_by_ids(
        self,
        *,
        organization_id: UUID,
        machine_id: UUID,
        exposure_ids: Iterable[UUID],
    ) -> int:
        ids = tuple(
            dict.fromkeys(
                exposure_ids
            )
        )

        self.delete_calls.append(
            {
                "organization_id": (
                    organization_id
                ),
                "machine_id": machine_id,
                "exposure_ids": ids,
            }
        )

        ids_set = set(
            ids
        )

        before = len(
            self.exposures
        )

        self.exposures = [
            exposure
            for exposure
            in self.exposures
            if exposure.id
            not in ids_set
        ]

        return (
            before
            - len(
                self.exposures
            )
        )


class FakeVulnerabilityExposureUnitOfWork:
    def __init__(
        self,
        *,
        cisa_repository: (
            FakeCisaKevApplicationReadRepository
        ),
        canonical_repository: (
            FakeCanonicalVulnerabilityRepository
        ),
        exposure_repository: (
            FakeVulnerabilityExposureRepository
        ),
    ) -> None:
        self.cisa_kev_applications = (
            cisa_repository
        )

        self.github_advisory_packages = (
            FakeGitHubAdvisoryPackageReadRepository()
        )

        self.canonical_vulnerabilities = (
            canonical_repository
        )

        self.vulnerability_exposures = (
            exposure_repository
        )

        self.enter_count = 0
        self.commit_count = 0
        self.rollback_count = 0

    def __enter__(
        self,
    ) -> FakeVulnerabilityExposureUnitOfWork:
        self.enter_count += 1
        return self

    def __exit__(
        self,
        exc_type,
        exc_value,
        traceback,
    ) -> None:
        del traceback

        if (
            exc_type is not None
            or exc_value is not None
        ):
            self.rollback()

    def commit(
        self,
    ) -> None:
        self.commit_count += 1

    def rollback(
        self,
    ) -> None:
        self.rollback_count += 1

    def reset(
        self,
    ) -> None:
        pass


def _application(
    *,
    machine_id: UUID,
    name: str = "Example Browser",
    vendor: str = "Example Corp",
    normalized_name: str | None = (
        "example browser"
    ),
    normalized_vendor: str | None = (
        "example corp"
    ),
    version: str | None = "1.5.0",
) -> SoftwareComponent:
    return SoftwareComponent(
        id=uuid4(),
        machine_id=machine_id,
        component_type="application",
        name=name,
        normalized_name=(
            normalized_name
        ),
        version=version,
        vendor=vendor,
        normalized_vendor=(
            normalized_vendor
        ),
        ecosystem=None,
        external_id=(
            "registry:test-app"
        ),
        scope=None,
        detected_by=(
            "windows_registry_uninstall"
        ),
        created_at=NOW,
        updated_at=NOW,
    )


def _package(
    *,
    machine_id: UUID,
) -> SoftwareComponent:
    return SoftwareComponent(
        id=uuid4(),
        machine_id=machine_id,
        component_type="package",
        name="requests",
        normalized_name="requests",
        version="2.31.0",
        vendor=None,
        normalized_vendor=None,
        ecosystem="pypi",
        external_id=None,
        scope="global",
        detected_by="pip_global",
        created_at=NOW,
        updated_at=NOW,
    )


def _candidate(
    *,
    cve_id: str = (
        "CVE-2026-10001"
    ),
    vendor_project: str = (
        "Example Corp"
    ),
    product: str = (
        "Example Browser"
    ),
    normalized_vendor_project: str = (
        "example corp"
    ),
    normalized_product: str = (
        "example browser"
    ),
) -> CisaKevApplicationCandidate:
    return CisaKevApplicationCandidate(
        cve_id=cve_id,
        vendor_project=vendor_project,
        product=product,
        normalized_vendor_project=(
            normalized_vendor_project
        ),
        normalized_product=(
            normalized_product
        ),
    )


def _canonical(
    *,
    cve_id: str = (
        "CVE-2026-10001"
    ),
) -> CanonicalVulnerability:
    return CanonicalVulnerability(
        id=uuid4(),
        identifiers=(
            VulnerabilityIdentifier(
                namespace="CVE",
                value=cve_id,
                is_primary=True,
            ),
        ),
        evidences=(
            VulnerabilityEvidence(
                source="cisa_kev",
                source_record_key=(
                    cve_id
                ),
                normalized_record_id=(
                    str(
                        uuid4()
                    )
                ),
                evidence_type=(
                    "known_exploited_vulnerability"
                ),
                correlation_rule=(
                    "exact_cve_identifier"
                ),
                observed_at=NOW,
                last_observed_at=NOW,
                source_published_at=None,
                source_modified_at=None,
                correlation_confidence=1.0,
            ),
        ),
        created_at=NOW,
        updated_at=NOW,
        status="active",
        correlation_version=1,
        merged_into_id=None,
    )


def _existing_exposure(
    *,
    component_id: UUID,
    canonical_id: UUID,
    match_rule: str = (
        CisaKevApplicationMatcher.MATCH_RULE
    ),
    applicability_status: str = (
        "potential"
    ),
    is_kev: bool = True,
) -> VulnerabilityExposure:
    return VulnerabilityExposure(
        id=uuid4(),
        software_component_id=(
            component_id
        ),
        canonical_vulnerability_id=(
            canonical_id
        ),
        applicability_status=(
            applicability_status
        ),
        match_rule=match_rule,
        match_version="1.5.0",
        severity=None,
        priority=None,
        is_kev=is_kev,
        first_detected_at=NOW,
        last_evaluated_at=NOW,
    )


def _service(
    *,
    candidates: Iterable[
        CisaKevApplicationCandidate
    ] = (),
    canonical_mapping: dict[
        tuple[str, str],
        CanonicalVulnerability,
    ]
    | None = None,
    existing_exposures: Iterable[
        VulnerabilityExposure
    ] = (),
):
    cisa_repository = (
        FakeCisaKevApplicationReadRepository(
            candidates=candidates
        )
    )

    canonical_repository = (
        FakeCanonicalVulnerabilityRepository(
            mapping=canonical_mapping
        )
    )

    exposure_repository = (
        FakeVulnerabilityExposureRepository(
            existing_exposures=(
                existing_exposures
            )
        )
    )

    unit_of_work = (
        FakeVulnerabilityExposureUnitOfWork(
            cisa_repository=(
                cisa_repository
            ),
            canonical_repository=(
                canonical_repository
            ),
            exposure_repository=(
                exposure_repository
            ),
        )
    )

    service = (
        ReconcileCisaKevApplicationExposuresService(
            unit_of_work=unit_of_work # pyright: ignore[reportArgumentType]
        )
    )

    return (
        service,
        unit_of_work,
        cisa_repository,
        canonical_repository,
        exposure_repository,
    )


def test_creates_potential_cisa_exposure_and_enriches_kev(
) -> None:
    organization_id = uuid4()
    machine_id = uuid4()

    application = _application(
        machine_id=machine_id
    )

    candidate = _candidate()
    canonical = _canonical()

    (
        service,
        unit_of_work,
        cisa_repository,
        canonical_repository,
        exposure_repository,
    ) = _service(
        candidates=[
            candidate,
        ],
        canonical_mapping={
            (
                "CVE",
                candidate.cve_id,
            ): canonical,
        },
    )

    result = service.reconcile(
        organization_id=organization_id,
        machine_id=machine_id,
        components=[
            application,
        ],
        evaluated_at=NOW,
    )

    assert (
        result.application_count
        == 1
    )

    assert (
        result.eligible_application_count
        == 1
    )

    assert (
        result.candidate_count
        == 1
    )

    assert result.match_count == 1

    assert (
        result.resolved_match_count
        == 1
    )

    assert (
        result.unresolved_match_count
        == 0
    )

    assert (
        result.upserted_exposure_count
        == 1
    )

    assert (
        result.kev_enriched_exposure_count
        == 1
    )

    assert (
        result.deleted_exposure_count
        == 0
    )

    assert cisa_repository.call_count == 1
    assert canonical_repository.call_count == 1

    assert len(
        exposure_repository.upsert_calls
    ) == 1

    detections = (
        exposure_repository
        .upsert_calls[0][
            "detections"
        ]
    )

    assert len(detections) == 1 # pyright: ignore[reportArgumentType]

    detection = detections[0] # pyright: ignore[reportIndexIssue]

    assert (
        detection.software_component_id
        == application.id
    )

    assert (
        detection.canonical_vulnerability_id
        == canonical.id
    )

    assert (
        detection.applicability_status
        == "potential"
    )

    assert (
        detection.match_rule
        == CisaKevApplicationMatcher.MATCH_RULE
    )

    assert (
        detection.match_version
        == application.version
    )

    # CISA ne décide pas de la severity.
    assert detection.severity is None

    assert len(
        exposure_repository.set_kev_calls
    ) == 1

    assert (
        exposure_repository
        .set_kev_calls[0][
            "is_kev"
        ]
        is True
    )

    persisted = next(
        exposure
        for exposure
        in exposure_repository.exposures
        if (
            exposure.software_component_id
            == application.id
        )
    )

    assert (
        persisted.applicability_status
        == "potential"
    )

    assert persisted.severity is None
    assert persisted.is_kev is True

    assert unit_of_work.commit_count == 1
    assert unit_of_work.rollback_count == 0


def test_cisa_does_not_degrade_existing_confirmed_exposure(
) -> None:
    organization_id = uuid4()
    machine_id = uuid4()

    application = _application(
        machine_id=machine_id
    )

    candidate = _candidate()
    canonical = _canonical()

    existing = _existing_exposure(
        component_id=application.id,
        canonical_id=canonical.id,
        match_rule=(
            "vendor_exact_version_confirmed_v1"
        ),
        applicability_status="confirmed",
        is_kev=False,
    )

    (
        service,
        unit_of_work,
        _,
        _,
        exposure_repository,
    ) = _service(
        candidates=[
            candidate,
        ],
        canonical_mapping={
            (
                "CVE",
                candidate.cve_id,
            ): canonical,
        },
        existing_exposures=[
            existing,
        ],
    )

    result = service.reconcile(
        organization_id=organization_id,
        machine_id=machine_id,
        components=[
            application,
        ],
        evaluated_at=NOW,
    )

    assert (
        result.preserved_foreign_exposure_count
        == 1
    )

    assert (
        result.upserted_exposure_count
        == 0
    )

    assert (
        result.kev_enriched_exposure_count
        == 1
    )

    assert (
        result.deleted_exposure_count
        == 0
    )

    assert not (
        exposure_repository.upsert_calls
    )

    assert len(
        exposure_repository.set_kev_calls
    ) == 1

    persisted = next(
        exposure
        for exposure
        in exposure_repository.exposures
        if exposure.id == existing.id
    )

    # Le signal CISA enrichit KEV,
    # mais ne dégrade jamais confirmed.
    assert (
        persisted.applicability_status
        == "confirmed"
    )

    assert (
        persisted.match_rule
        == "vendor_exact_version_confirmed_v1"
    )

    assert persisted.is_kev is True

    assert unit_of_work.commit_count == 1


def test_deletes_only_stale_cisa_exposure(
) -> None:
    organization_id = uuid4()
    machine_id = uuid4()

    application = _application(
        machine_id=machine_id
    )

    stale_cisa = _existing_exposure(
        component_id=application.id,
        canonical_id=uuid4(),
        match_rule=(
            CisaKevApplicationMatcher.MATCH_RULE
        ),
    )

    unrelated = _existing_exposure(
        component_id=application.id,
        canonical_id=uuid4(),
        match_rule=(
            "other_application_rule_v1"
        ),
        applicability_status="confirmed",
        is_kev=False,
    )

    (
        service,
        unit_of_work,
        cisa_repository,
        canonical_repository,
        exposure_repository,
    ) = _service(
        candidates=(),
        canonical_mapping={},
        existing_exposures=[
            stale_cisa,
            unrelated,
        ],
    )

    result = service.reconcile(
        organization_id=organization_id,
        machine_id=machine_id,
        components=[
            application,
        ],
        evaluated_at=NOW,
    )

    assert cisa_repository.call_count == 1

    assert (
        canonical_repository.call_count
        == 0
    )

    assert result.match_count == 0

    assert (
        result.deleted_exposure_count
        == 1
    )

    assert len(
        exposure_repository.delete_calls
    ) == 1

    assert (
        exposure_repository
        .delete_calls[0][
            "exposure_ids"
        ]
        == (
            stale_cisa.id,
        )
    )

    remaining_ids = {
        exposure.id
        for exposure
        in exposure_repository.exposures
    }

    assert stale_cisa.id not in (
        remaining_ids
    )

    assert unrelated.id in remaining_ids

    assert unit_of_work.commit_count == 1


def test_unresolved_canonical_preserves_existing_cisa_exposure(
) -> None:
    organization_id = uuid4()
    machine_id = uuid4()

    application = _application(
        machine_id=machine_id
    )

    candidate = _candidate()

    existing = _existing_exposure(
        component_id=application.id,
        canonical_id=uuid4(),
    )

    (
        service,
        unit_of_work,
        _,
        canonical_repository,
        exposure_repository,
    ) = _service(
        candidates=[
            candidate,
        ],
        canonical_mapping={},
        existing_exposures=[
            existing,
        ],
    )

    result = service.reconcile(
        organization_id=organization_id,
        machine_id=machine_id,
        components=[
            application,
        ],
        evaluated_at=NOW,
    )

    assert result.match_count == 1

    assert (
        result.resolved_match_count
        == 0
    )

    assert (
        result.unresolved_match_count
        == 1
    )

    assert (
        result.deleted_exposure_count
        == 0
    )

    assert canonical_repository.call_count == 1

    assert not (
        exposure_repository.upsert_calls
    )

    assert not (
        exposure_repository.delete_calls
    )

    assert existing in (
        exposure_repository.exposures
    )

    assert unit_of_work.commit_count == 1


def test_application_without_normalized_identity_removes_old_cisa_exposure(
) -> None:
    organization_id = uuid4()
    machine_id = uuid4()

    application = _application(
        machine_id=machine_id,
        normalized_name=None,
        normalized_vendor=None,
    )

    existing = _existing_exposure(
        component_id=application.id,
        canonical_id=uuid4(),
    )

    (
        service,
        unit_of_work,
        cisa_repository,
        canonical_repository,
        exposure_repository,
    ) = _service(
        existing_exposures=[
            existing,
        ],
    )

    result = service.reconcile(
        organization_id=organization_id,
        machine_id=machine_id,
        components=[
            application,
        ],
        evaluated_at=NOW,
    )

    assert (
        result.application_count
        == 1
    )

    assert (
        result.eligible_application_count
        == 0
    )

    # Pas de clé vendor/product exploitable :
    # aucun accès CISA nécessaire.
    assert cisa_repository.call_count == 0

    assert (
        canonical_repository.call_count
        == 0
    )

    assert (
        result.deleted_exposure_count
        == 1
    )

    assert (
        existing.id
        not in {
            exposure.id
            for exposure
            in exposure_repository.exposures
        }
    )

    assert unit_of_work.commit_count == 1


def test_only_packages_do_not_open_unit_of_work(
) -> None:
    machine_id = uuid4()

    package = _package(
        machine_id=machine_id
    )

    (
        service,
        unit_of_work,
        cisa_repository,
        canonical_repository,
        exposure_repository,
    ) = _service()

    result = service.reconcile(
        organization_id=uuid4(),
        machine_id=machine_id,
        components=[
            package,
        ],
        evaluated_at=NOW,
    )

    assert result.application_count == 0

    assert unit_of_work.enter_count == 0

    assert cisa_repository.call_count == 0

    assert (
        canonical_repository.call_count
        == 0
    )

    assert not exposure_repository.list_calls
    assert not exposure_repository.upsert_calls
    assert not exposure_repository.delete_calls
    assert not exposure_repository.set_kev_calls


def test_machine_scope_mismatch_is_rejected_before_unit_of_work(
) -> None:
    expected_machine_id = uuid4()

    application = _application(
        machine_id=uuid4()
    )

    (
        service,
        unit_of_work,
        cisa_repository,
        canonical_repository,
        exposure_repository,
    ) = _service()

    with pytest.raises(
        ValueError,
        match=(
            "Software component machine "
            "scope mismatch"
        ),
    ):
        service.reconcile(
            organization_id=uuid4(),
            machine_id=(
                expected_machine_id
            ),
            components=[
                application,
            ],
            evaluated_at=NOW,
        )

    assert unit_of_work.enter_count == 0

    assert cisa_repository.call_count == 0

    assert (
        canonical_repository.call_count
        == 0
    )

    assert not exposure_repository.list_calls
    assert not exposure_repository.upsert_calls
    assert not exposure_repository.delete_calls
    assert not exposure_repository.set_kev_calls