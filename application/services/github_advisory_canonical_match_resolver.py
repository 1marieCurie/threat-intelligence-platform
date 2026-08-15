from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from uuid import UUID

from application.ports.outbound.canonical_vulnerability_repository import (
    CanonicalVulnerabilityRepository,
)
from application.services.github_advisory_package_matcher import (
    GitHubAdvisoryPackageMatch,
)
from domain.canonical_vulnerability import (
    CanonicalVulnerability,
)
from domain.vulnerability_identifier import (
    VulnerabilityIdentifier,
)


class GitHubAdvisoryCanonicalResolutionError(
    RuntimeError
):
    pass


class GitHubAdvisoryCanonicalResolutionConflictError(
    GitHubAdvisoryCanonicalResolutionError
):
    """
    Un CVE et un GHSA d'un même match ne doivent
    jamais appartenir à deux vulnérabilités
    canoniques différentes.
    """


@dataclass(
    frozen=True,
    slots=True,
)
class ResolvedGitHubAdvisoryPackageMatch:
    match: GitHubAdvisoryPackageMatch
    canonical_vulnerability_id: UUID


@dataclass(
    frozen=True,
    slots=True,
)
class GitHubAdvisoryCanonicalResolutionResult:
    resolved: tuple[
        ResolvedGitHubAdvisoryPackageMatch,
        ...,
    ]

    unresolved: tuple[
        GitHubAdvisoryPackageMatch,
        ...,
    ]


class GitHubAdvisoryCanonicalMatchResolver:
    """
    Résout en batch les matches GitHub Advisory
    vers les CanonicalVulnerability existantes.

    Ce service :
    - ne crée aucune vulnérabilité ;
    - ne fait aucune corrélation fournisseur ;
    - réutilise le repository canonique existant ;
    - vérifie la cohérence CVE/GHSA ;
    - ignore les vulnérabilités non actionnables.
    """

    ACTIONABLE_STATUSES = frozenset(
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
            GitHubAdvisoryPackageMatch
        ],
    ) -> GitHubAdvisoryCanonicalResolutionResult:
        normalized_matches = (
            self._normalize_matches(
                matches
            )
        )

        if not normalized_matches:
            return (
                GitHubAdvisoryCanonicalResolutionResult(
                    resolved=(),
                    unresolved=(),
                )
            )

        identifiers_by_match: dict[
            int,
            tuple[
                VulnerabilityIdentifier,
                ...,
            ],
        ] = {}

        identifiers_by_key: dict[
            tuple[str, str],
            VulnerabilityIdentifier,
        ] = {}

        for index, match in enumerate(
            normalized_matches
        ):
            identifiers = (
                self._identifiers_for_match(
                    match
                )
            )

            identifiers_by_match[
                index
            ] = identifiers

            for identifier in identifiers:
                identifiers_by_key.setdefault(
                    identifier.key,
                    identifier,
                )

        resolved_by_identifier = (
            self._repository
            .find_many_by_identifiers(
                identifiers_by_key.values()
            )
        )

        resolved: list[
            ResolvedGitHubAdvisoryPackageMatch
        ] = []

        unresolved: list[
            GitHubAdvisoryPackageMatch
        ] = []

        for index, match in enumerate(
            normalized_matches
        ):
            identifiers = (
                identifiers_by_match[index]
            )

            canonical = (
                self._resolve_match_canonical(
                    match=match,
                    identifiers=identifiers,
                    resolved_by_identifier=(
                        resolved_by_identifier
                    ),
                )
            )

            if canonical is None:
                unresolved.append(
                    match
                )
                continue

            if (
                canonical.status
                not in self.ACTIONABLE_STATUSES
            ):
                unresolved.append(
                    match
                )
                continue

            resolved.append(
                ResolvedGitHubAdvisoryPackageMatch(
                    match=match,
                    canonical_vulnerability_id=(
                        canonical.id
                    ),
                )
            )

        return (
            GitHubAdvisoryCanonicalResolutionResult(
                resolved=tuple(
                    resolved
                ),
                unresolved=tuple(
                    unresolved
                ),
            )
        )

    @staticmethod
    def _normalize_matches(
        matches: Iterable[
            GitHubAdvisoryPackageMatch
        ],
    ) -> tuple[
        GitHubAdvisoryPackageMatch,
        ...,
    ]:
        if isinstance(
            matches,
            (str, bytes),
        ):
            raise TypeError(
                "matches must be an iterable of "
                "GitHubAdvisoryPackageMatch"
            )

        try:
            normalized = tuple(
                matches
            )
        except TypeError as error:
            raise TypeError(
                "matches must be iterable"
            ) from error

        for match in normalized:
            if not isinstance(
                match,
                GitHubAdvisoryPackageMatch,
            ):
                raise TypeError(
                    "Every match must be a "
                    "GitHubAdvisoryPackageMatch"
                )

        return normalized

    @classmethod
    def _identifiers_for_match(
        cls,
        match: GitHubAdvisoryPackageMatch,
    ) -> tuple[
        VulnerabilityIdentifier,
        ...,
    ]:
        identifiers: list[
            VulnerabilityIdentifier
        ] = []

        if match.cve_id is not None:
            identifier = (
                cls._safe_identifier(
                    namespace="CVE",
                    value=match.cve_id,
                )
            )

            if identifier is not None:
                identifiers.append(
                    identifier
                )

        ghsa_identifier = (
            cls._safe_identifier(
                namespace="GHSA",
                value=match.ghsa_id,
            )
        )

        if ghsa_identifier is not None:
            identifiers.append(
                ghsa_identifier
            )

        return tuple(
            identifiers
        )

    @staticmethod
    def _safe_identifier(
        *,
        namespace: str,
        value: str,
    ) -> VulnerabilityIdentifier | None:
        try:
            return VulnerabilityIdentifier(
                namespace=namespace,
                value=value,
                is_primary=False,
            )

        except (
            TypeError,
            ValueError,
        ):
            return None

    @staticmethod
    def _resolve_match_canonical(
        *,
        match: GitHubAdvisoryPackageMatch,
        identifiers: tuple[
            VulnerabilityIdentifier,
            ...,
        ],
        resolved_by_identifier: dict[
            tuple[str, str],
            CanonicalVulnerability,
        ],
    ) -> CanonicalVulnerability | None:
        canonicals: dict[
            UUID,
            CanonicalVulnerability,
        ] = {}

        for identifier in identifiers:
            canonical = (
                resolved_by_identifier.get(
                    identifier.key
                )
            )

            if canonical is not None:
                canonicals[
                    canonical.id
                ] = canonical

        if not canonicals:
            return None

        if len(canonicals) > 1:
            raise (
                GitHubAdvisoryCanonicalResolutionConflictError(
                    "CVE and GHSA from the same "
                    "GitHub Advisory match resolve "
                    "to different canonical "
                    "vulnerabilities: "
                    f"{match.ghsa_id}"
                )
            )

        return next(
            iter(
                canonicals.values()
            )
        )