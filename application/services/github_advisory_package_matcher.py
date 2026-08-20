from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from uuid import UUID

from packaging.specifiers import (
    InvalidSpecifier,
    SpecifierSet,
)
from packaging.version import (
    InvalidVersion,
    Version,
)

from application.ports.outbound.github_advisory_package_read_repository import (
    GitHubAdvisoryPackageCandidate,
)
from application.services.software_component_normalizer import (
    SoftwareComponentNormalizer,
)
from domain.software_component import (
    SoftwareComponent,
)


@dataclass(
    frozen=True,
    slots=True,
)
class GitHubAdvisoryPackageMatch:
    software_component_id: UUID

    ghsa_id: str
    cve_id: str | None

    applicability_status: str
    match_rule: str
    match_version: str

    vulnerable_version_range: str
    first_patched_version: str | None

    severity: str | None


class GitHubAdvisoryPackageMatcher:
    """
    Matcher déterministe V1 pour les packages
    PyPI et npm.

    Une exposition est confirmée uniquement lorsque :
    - le composant appartient à un écosystème supporté ;
    - le nom du package correspond exactement après
      normalisation déterministe propre à l'écosystème ;
    - la version installée est vérifiable ;
    - la version appartient explicitement à la plage
      vulnérable GitHub Advisory.

    Aucun fuzzy matching, aucune IA et aucune
    approximation de version.

    Pour npm, les plages de versions non interprétables
    par notre parseur conservateur ne produisent jamais
    d'exposition confirmée.
    """

    MATCH_RULE_PYPI = (
        "github_advisory_pypi_"
        "exact_package_version_range_v1"
    )

    MATCH_RULE_NPM = (
        "github_advisory_npm_"
        "exact_package_version_range_v1"
    )

    # Compatibilité avec les consommateurs V1 qui
    # référencent encore MATCH_RULE directement.
    MATCH_RULE = MATCH_RULE_PYPI

    APPLICABILITY_STATUS = "confirmed"

    _SUPPORTED_ECOSYSTEMS = {
        "pypi",
        "npm",
    }

    _ECOSYSTEM_ALIASES = {
        "pip": "pypi",
        "pypi": "pypi",
        "npm": "npm",
    }

    _SEVERITY_MAP = {
        "NONE": "NONE",
        "UNKNOWN": None,
        "LOW": "LOW",
        "MODERATE": "MEDIUM",
        "MEDIUM": "MEDIUM",
        "HIGH": "HIGH",
        "CRITICAL": "CRITICAL",
    }

    def __init__(
        self,
        *,
        normalizer: (
            SoftwareComponentNormalizer | None
        ) = None,
    ) -> None:
        self._normalizer = (
            normalizer
            or SoftwareComponentNormalizer()
        )

    def match(
        self,
        *,
        component: SoftwareComponent,
        candidates: Iterable[
            GitHubAdvisoryPackageCandidate
        ],
    ) -> tuple[
        GitHubAdvisoryPackageMatch,
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
                "of GitHubAdvisoryPackageCandidate"
            )

        try:
            candidate_list = tuple(
                candidates
            )

        except TypeError as error:
            raise TypeError(
                "candidates must be iterable"
            ) from error

        for candidate in candidate_list:
            if not isinstance(
                candidate,
                GitHubAdvisoryPackageCandidate,
            ):
                raise TypeError(
                    "Every candidate must be a "
                    "GitHubAdvisoryPackageCandidate"
                )

        installed_version = (
            self._parse_installed_version(
                component.version  # type: ignore[arg-type]
            )
        )

        if installed_version is None:
            # Pas de preuve fiable de vulnérabilité.
            return ()

        matches: list[
            GitHubAdvisoryPackageMatch
        ] = []

        for candidate in candidate_list:
            match = self._match_candidate(
                component=component,
                installed_version=(
                    installed_version
                ),
                candidate=candidate,
            )

            if match is not None:
                matches.append(
                    match
                )

        return self._deduplicate_matches(
            matches
        )

    def _match_candidate(
        self,
        *,
        component: SoftwareComponent,
        installed_version: Version,
        candidate: (
            GitHubAdvisoryPackageCandidate
        ),
    ) -> (
        GitHubAdvisoryPackageMatch | None
    ):
        candidate_ecosystem = (
            self._normalize_candidate_ecosystem(
                candidate.ecosystem
            )
        )

        if (
            candidate_ecosystem
            != component.ecosystem
        ):
            return None

        candidate_name = (
            self._normalize_candidate_name(
                package_name=(
                    candidate.package_name
                ),
                ecosystem=(
                    component.ecosystem
                ),
            )
        )

        if candidate_name is None:
            return None

        if (
            candidate_name
            != component.normalized_name
        ):
            return None

        if not self._is_vulnerable_version(
            installed_version=(
                installed_version
            ),
            vulnerable_version_range=(
                candidate
                .vulnerable_version_range
            ),
        ):
            return None

        ghsa_id = (
            candidate.ghsa_id
            .strip()
            .upper()
        )

        cve_id = (
            None
            if candidate.cve_id is None
            else candidate.cve_id
            .strip()
            .upper()
        )

        severity = (
            self._normalize_severity(
                candidate.severity
            )
        )

        match_rule = (
            self._match_rule_for_ecosystem(
                component.ecosystem
            )
        )

        return GitHubAdvisoryPackageMatch(
            software_component_id=(
                component.id
            ),
            ghsa_id=ghsa_id,
            cve_id=cve_id,
            applicability_status=(
                self.APPLICABILITY_STATUS
            ),
            match_rule=match_rule,
            match_version=(
                component.version
            ),  # type: ignore[arg-type]
            vulnerable_version_range=(
                candidate
                .vulnerable_version_range
            ),
            first_patched_version=(
                candidate
                .first_patched_version
            ),
            severity=severity,
        )

    @classmethod
    def _match_rule_for_ecosystem(
        cls,
        ecosystem: str | None,
    ) -> str:
        if ecosystem == "pypi":
            return cls.MATCH_RULE_PYPI

        if ecosystem == "npm":
            return cls.MATCH_RULE_NPM

        raise ValueError(
            "Unsupported package ecosystem"
        )

    @classmethod
    def _normalize_severity(
        cls,
        severity: str | None,
    ) -> str | None:
        if not isinstance(
            severity,
            str,
        ):
            return None

        normalized = (
            severity
            .strip()
            .upper()
        )

        if not normalized:
            return None

        return cls._SEVERITY_MAP.get(
            normalized
        )

    @classmethod
    def _validate_component(
        cls,
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
            != "package"
        ):
            raise ValueError(
                "component must be a package"
            )

        if (
            component.ecosystem
            not in cls._SUPPORTED_ECOSYSTEMS
        ):
            raise ValueError(
                "GitHubAdvisoryPackageMatcher "
                "V1 supports only pypi and npm"
            )

        if component.version is None:
            raise ValueError(
                "package version is required"
            )

        if (
            component.normalized_name
            is None
        ):
            raise ValueError(
                "package normalized_name "
                "is required"
            )

    @staticmethod
    def _parse_installed_version(
        version: str,
    ) -> Version | None:
        try:
            return Version(
                version
            )

        except InvalidVersion:
            return None

    def _normalize_candidate_name(
        self,
        *,
        package_name: str,
        ecosystem: str | None,
    ) -> str | None:
        if not isinstance(
            package_name,
            str,
        ):
            return None

        if ecosystem not in {
            "pypi",
            "npm",
        }:
            return None

        try:
            result = (
                self._normalizer.normalize(
                    component_type="package",
                    name=package_name,
                    vendor=None,
                    ecosystem=ecosystem,
                )
            )

        except (
            TypeError,
            ValueError,
        ):
            return None

        return result.normalized_name

    @classmethod
    def _normalize_candidate_ecosystem(
        cls,
        ecosystem: str,
    ) -> str | None:
        if not isinstance(
            ecosystem,
            str,
        ):
            return None

        normalized = (
            ecosystem
            .strip()
            .lower()
        )

        return (
            cls._ECOSYSTEM_ALIASES
            .get(
                normalized
            )
        )

    @classmethod
    def _is_vulnerable_version(
        cls,
        *,
        installed_version: Version,
        vulnerable_version_range: str,
    ) -> bool:
        normalized_range = (
            cls._normalize_version_range(
                vulnerable_version_range
            )
        )

        if normalized_range is None:
            return False

        try:
            specifiers = SpecifierSet(
                normalized_range
            )

        except InvalidSpecifier:
            return False

        return specifiers.contains(
            installed_version,
            prereleases=True,
        )

    @staticmethod
    def _normalize_version_range(
        vulnerable_version_range: str,
    ) -> str | None:
        if not isinstance(
            vulnerable_version_range,
            str,
        ):
            return None

        parts: list[str] = []

        for raw_part in (
            vulnerable_version_range
            .split(",")
        ):
            part = " ".join(
                raw_part
                .strip()
                .split()
            )

            if not part:
                return None

            # Tolérance conservatrice pour une
            # égalité simple provenant de la source.
            if (
                part.startswith("=")
                and not part.startswith("==")
            ):
                part = (
                    "=="
                    + part[1:].lstrip()
                )

            parts.append(
                part
            )

        if not parts:
            return None

        return ",".join(
            parts
        )

    @staticmethod
    def _deduplicate_matches(
        matches: list[
            GitHubAdvisoryPackageMatch
        ],
    ) -> tuple[
        GitHubAdvisoryPackageMatch,
        ...,
    ]:
        ordered_matches = sorted(
            matches,
            key=lambda match: (
                match.ghsa_id,
                match.cve_id or "",
                match.vulnerable_version_range,
            ),
        )

        unique: dict[
            str,
            GitHubAdvisoryPackageMatch,
        ] = {}

        for match in ordered_matches:
            unique.setdefault(
                match.ghsa_id,
                match,
            )

        return tuple(
            unique.values()
        )