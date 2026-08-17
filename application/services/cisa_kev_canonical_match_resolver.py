from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from uuid import UUID

from application.ports.outbound.canonical_vulnerability_repository import (
    CanonicalVulnerabilityRepository,
)
from application.services.cisa_kev_application_matcher import (
    CisaKevApplicationMatch,
)
from domain.vulnerability_identifier import (
    VulnerabilityIdentifier,
)


@dataclass(
    frozen=True,
    slots=True,
)
class ResolvedCisaKevApplicationMatch:
    match: CisaKevApplicationMatch

    canonical_vulnerability_id: UUID


@dataclass(
    frozen=True,
    slots=True,
)
class CisaKevCanonicalResolutionResult:
    resolved: tuple[
        ResolvedCisaKevApplicationMatch,
        ...,
    ]

    unresolved: tuple[
        CisaKevApplicationMatch,
        ...,
    ]


class CisaKevCanonicalMatchResolver:
    """
    Résout les CVE issues du matching CISA KEV
    vers les CanonicalVulnerability existantes.

    Le resolver :
    - ne crée aucune vulnérabilité canonique ;
    - effectue une seule résolution batch ;
    - accepte uniquement les canonical
      provisional ou active ;
    - traite withdrawn/rejected/merged comme
      non exploitables pour une exposition V1.
    """

    _ACTIONABLE_STATUSES = frozenset(
        {
            "provisional",
            "active",
        }
    )

    def __init__(
        self,
        *,
        canonical_vulnerability_repository: (
            CanonicalVulnerabilityRepository
        ),
    ) -> None:
        if (
            canonical_vulnerability_repository
            is None
        ):
            raise ValueError(
                "canonical_vulnerability_repository "
                "must not be None"
            )

        self._repository = (
            canonical_vulnerability_repository
        )

    def resolve(
        self,
        *,
        matches: Iterable[
            CisaKevApplicationMatch
        ],
    ) -> CisaKevCanonicalResolutionResult:
        if isinstance(
            matches,
            (str, bytes),
        ):
            raise TypeError(
                "matches must be an iterable "
                "of CisaKevApplicationMatch"
            )

        try:
            submitted_matches = tuple(
                matches
            )
        except TypeError as error:
            raise TypeError(
                "matches must be iterable"
            ) from error

        for match in submitted_matches:
            if not isinstance(
                match,
                CisaKevApplicationMatch,
            ):
                raise TypeError(
                    "Every match must be a "
                    "CisaKevApplicationMatch"
                )

        if not submitted_matches:
            return (
                CisaKevCanonicalResolutionResult(
                    resolved=(),
                    unresolved=(),
                )
            )

        identifiers_by_cve: dict[
            str,
            VulnerabilityIdentifier,
        ] = {}

        for match in submitted_matches:
            identifier = (
                self._safe_cve_identifier(
                    match.cve_id
                )
            )

            if identifier is None:
                continue

            identifiers_by_cve.setdefault(
                identifier.value,
                identifier,
            )

        if identifiers_by_cve:
            canonical_by_identifier = (
                self._repository
                .find_many_by_identifiers(
                    identifiers_by_cve.values()
                )
            )
        else:
            canonical_by_identifier = {}

        resolved: list[
            ResolvedCisaKevApplicationMatch
        ] = []

        unresolved: list[
            CisaKevApplicationMatch
        ] = []

        for match in submitted_matches:
            identifier = (
                self._safe_cve_identifier(
                    match.cve_id
                )
            )

            if identifier is None:
                unresolved.append(
                    match
                )
                continue

            canonical = (
                canonical_by_identifier.get(
                    identifier.key
                )
            )

            if canonical is None:
                unresolved.append(
                    match
                )
                continue

            if (
                canonical.status
                not in self._ACTIONABLE_STATUSES
            ):
                unresolved.append(
                    match
                )
                continue

            resolved.append(
                ResolvedCisaKevApplicationMatch(
                    match=match,
                    canonical_vulnerability_id=(
                        canonical.id
                    ),
                )
            )

        return (
            CisaKevCanonicalResolutionResult(
                resolved=tuple(
                    resolved
                ),
                unresolved=tuple(
                    unresolved
                ),
            )
        )

    @staticmethod
    def _safe_cve_identifier(
        value: str,
    ) -> VulnerabilityIdentifier | None:
        try:
            return VulnerabilityIdentifier(
                namespace="CVE",
                value=value,
                is_primary=False,
            )
        except (
            TypeError,
            ValueError,
        ):
            return None