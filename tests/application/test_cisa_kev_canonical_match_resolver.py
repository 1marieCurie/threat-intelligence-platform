from __future__ import annotations

from collections.abc import Iterable
from datetime import (
    UTC,
    datetime,
)
from uuid import UUID, uuid4

from application.services.cisa_kev_application_matcher import (
    CisaKevApplicationMatch,
)
from application.services.cisa_kev_canonical_match_resolver import (
    CisaKevCanonicalMatchResolver,
)
from domain.canonical_vulnerability import (
    CanonicalVulnerability,
)
from domain.vulnerability_evidence import (
    VulnerabilityEvidence,
)
from domain.vulnerability_identifier import (
    VulnerabilityIdentifier,
)


NOW = datetime(
    2026,
    8,
    17,
    13,
    0,
    tzinfo=UTC,
)


class FakeCanonicalVulnerabilityRepository:
    """
    Fake conforme au port
    CanonicalVulnerabilityRepository.

    Seule find_many_by_identifiers() est attendue
    dans ces tests.

    Les autres méthodes lèvent volontairement une
    AssertionError : si le resolver commence à les
    appeler, le test doit le signaler immédiatement.
    """

    def __init__(
        self,
        *,
        vulnerabilities: (
            dict[
                tuple[str, str],
                CanonicalVulnerability,
            ]
            | None
        ) = None,
    ) -> None:
        self.vulnerabilities = (
            vulnerabilities
            or {}
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
            "by CisaKevCanonicalMatchResolver"
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
            "by CisaKevCanonicalMatchResolver"
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
            identifier.key: (
                self.vulnerabilities[
                    identifier.key
                ]
            )
            for identifier
            in self.requested_identifiers
            if (
                identifier.key
                in self.vulnerabilities
            )
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
            "be called by "
            "CisaKevCanonicalMatchResolver"
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
            "by CisaKevCanonicalMatchResolver"
        )


def _match(
    *,
    cve_id: str = (
        "CVE-2026-12345"
    ),
) -> CisaKevApplicationMatch:
    return CisaKevApplicationMatch(
        software_component_id=uuid4(),
        cve_id=cve_id,
        applicability_status="potential",
        match_rule=(
            "cisa_kev_exact_vendor_product_v1"
        ),
        match_version="140.0.0",
        is_kev=True,
    )


def _canonical(
    *,
    cve_id: str = (
        "CVE-2026-12345"
    ),
    status: str = "active",
) -> CanonicalVulnerability:
    vulnerability_id = uuid4()

    return CanonicalVulnerability(
        id=vulnerability_id,
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
                normalized_record_id=str(
                    uuid4()
                ),
                evidence_type=(
                    "known_exploited_vulnerability"
                ),
                correlation_rule=(
                    "exact_cve"
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
        status=status,
        correlation_version=1,
        merged_into_id=(
            uuid4()
            if status == "merged"
            else None
        ),
    )


def test_resolves_cve_to_active_canonical(
) -> None:
    match = _match()

    canonical = _canonical()

    repository = (
        FakeCanonicalVulnerabilityRepository(
            vulnerabilities={
                (
                    "CVE",
                    match.cve_id,
                ): canonical
            }
        )
    )

    resolver = (
        CisaKevCanonicalMatchResolver(
            canonical_vulnerability_repository=(
                repository
            )
        )
    )

    result = resolver.resolve(
        matches=[
            match
        ]
    )

    assert len(
        result.resolved
    ) == 1

    assert (
        result.resolved[0]
        .canonical_vulnerability_id
        == canonical.id
    )

    assert (
        result.resolved[0].match
        == match
    )

    assert (
        result.unresolved
        == ()
    )

    assert (
        repository.call_count
        == 1
    )


def test_provisional_canonical_is_actionable(
) -> None:
    match = _match()

    canonical = _canonical(
        status="provisional"
    )

    repository = (
        FakeCanonicalVulnerabilityRepository(
            vulnerabilities={
                (
                    "CVE",
                    match.cve_id,
                ): canonical
            }
        )
    )

    resolver = (
        CisaKevCanonicalMatchResolver(
            canonical_vulnerability_repository=(
                repository
            )
        )
    )

    result = resolver.resolve(
        matches=[
            match
        ]
    )

    assert len(
        result.resolved
    ) == 1

    assert (
        result.resolved[0]
        .canonical_vulnerability_id
        == canonical.id
    )

    assert (
        result.unresolved
        == ()
    )


def test_missing_canonical_is_unresolved(
) -> None:
    match = _match()

    repository = (
        FakeCanonicalVulnerabilityRepository()
    )

    resolver = (
        CisaKevCanonicalMatchResolver(
            canonical_vulnerability_repository=(
                repository
            )
        )
    )

    result = resolver.resolve(
        matches=[
            match
        ]
    )

    assert (
        result.resolved
        == ()
    )

    assert (
        result.unresolved
        == (
            match,
        )
    )

    assert (
        repository.call_count
        == 1
    )


def test_withdrawn_canonical_is_unresolved(
) -> None:
    match = _match()

    canonical = _canonical(
        status="withdrawn"
    )

    repository = (
        FakeCanonicalVulnerabilityRepository(
            vulnerabilities={
                (
                    "CVE",
                    match.cve_id,
                ): canonical
            }
        )
    )

    resolver = (
        CisaKevCanonicalMatchResolver(
            canonical_vulnerability_repository=(
                repository
            )
        )
    )

    result = resolver.resolve(
        matches=[
            match
        ]
    )

    assert (
        result.resolved
        == ()
    )

    assert (
        result.unresolved
        == (
            match,
        )
    )


def test_rejected_canonical_is_unresolved(
) -> None:
    match = _match()

    canonical = _canonical(
        status="rejected"
    )

    repository = (
        FakeCanonicalVulnerabilityRepository(
            vulnerabilities={
                (
                    "CVE",
                    match.cve_id,
                ): canonical
            }
        )
    )

    resolver = (
        CisaKevCanonicalMatchResolver(
            canonical_vulnerability_repository=(
                repository
            )
        )
    )

    result = resolver.resolve(
        matches=[
            match
        ]
    )

    assert (
        result.resolved
        == ()
    )

    assert (
        result.unresolved
        == (
            match,
        )
    )


def test_merged_canonical_is_unresolved(
) -> None:
    match = _match()

    canonical = _canonical(
        status="merged"
    )

    repository = (
        FakeCanonicalVulnerabilityRepository(
            vulnerabilities={
                (
                    "CVE",
                    match.cve_id,
                ): canonical
            }
        )
    )

    resolver = (
        CisaKevCanonicalMatchResolver(
            canonical_vulnerability_repository=(
                repository
            )
        )
    )

    result = resolver.resolve(
        matches=[
            match
        ]
    )

    assert (
        result.resolved
        == ()
    )

    assert (
        result.unresolved
        == (
            match,
        )
    )


def test_multiple_cves_use_single_batch_lookup(
) -> None:
    first_match = _match(
        cve_id="CVE-2026-10001"
    )

    second_match = _match(
        cve_id="CVE-2026-10002"
    )

    first_canonical = _canonical(
        cve_id="CVE-2026-10001"
    )

    second_canonical = _canonical(
        cve_id="CVE-2026-10002"
    )

    repository = (
        FakeCanonicalVulnerabilityRepository(
            vulnerabilities={
                (
                    "CVE",
                    "CVE-2026-10001",
                ): first_canonical,
                (
                    "CVE",
                    "CVE-2026-10002",
                ): second_canonical,
            }
        )
    )

    resolver = (
        CisaKevCanonicalMatchResolver(
            canonical_vulnerability_repository=(
                repository
            )
        )
    )

    result = resolver.resolve(
        matches=[
            first_match,
            second_match,
        ]
    )

    assert (
        repository.call_count
        == 1
    )

    assert len(
        repository.requested_identifiers
    ) == 2

    assert {
        identifier.key
        for identifier
        in repository.requested_identifiers
    } == {
        (
            "CVE",
            "CVE-2026-10001",
        ),
        (
            "CVE",
            "CVE-2026-10002",
        ),
    }

    assert len(
        result.resolved
    ) == 2

    assert (
        result.unresolved
        == ()
    )


def test_duplicate_cve_is_looked_up_once(
) -> None:
    first_match = _match(
        cve_id="CVE-2026-12345"
    )

    second_match = (
        CisaKevApplicationMatch(
            software_component_id=uuid4(),
            cve_id="CVE-2026-12345",
            applicability_status="potential",
            match_rule=(
                "cisa_kev_exact_vendor_product_v1"
            ),
            match_version="141.0.0",
            is_kev=True,
        )
    )

    canonical = _canonical()

    repository = (
        FakeCanonicalVulnerabilityRepository(
            vulnerabilities={
                (
                    "CVE",
                    "CVE-2026-12345",
                ): canonical
            }
        )
    )

    resolver = (
        CisaKevCanonicalMatchResolver(
            canonical_vulnerability_repository=(
                repository
            )
        )
    )

    result = resolver.resolve(
        matches=[
            first_match,
            second_match,
        ]
    )

    assert (
        repository.call_count
        == 1
    )

    assert len(
        repository.requested_identifiers
    ) == 1

    assert (
        repository
        .requested_identifiers[0]
        .key
        == (
            "CVE",
            "CVE-2026-12345",
        )
    )

    # Même CVE mais deux composants.
    # Deux expositions restent donc
    # légitimes.
    assert len(
        result.resolved
    ) == 2


def test_invalid_cve_becomes_unresolved_without_crash(
) -> None:
    match = _match(
        cve_id="not-a-cve"
    )

    repository = (
        FakeCanonicalVulnerabilityRepository()
    )

    resolver = (
        CisaKevCanonicalMatchResolver(
            canonical_vulnerability_repository=(
                repository
            )
        )
    )

    result = resolver.resolve(
        matches=[
            match
        ]
    )

    assert (
        result.resolved
        == ()
    )

    assert (
        result.unresolved
        == (
            match,
        )
    )

    # Aucun identifiant CVE valide :
    # aucune requête au repository.
    assert (
        repository.call_count
        == 0
    )


def test_empty_input_does_not_call_repository(
) -> None:
    repository = (
        FakeCanonicalVulnerabilityRepository()
    )

    resolver = (
        CisaKevCanonicalMatchResolver(
            canonical_vulnerability_repository=(
                repository
            )
        )
    )

    result = resolver.resolve(
        matches=[]
    )

    assert (
        result.resolved
        == ()
    )

    assert (
        result.unresolved
        == ()
    )

    assert (
        repository.call_count
        == 0
    )