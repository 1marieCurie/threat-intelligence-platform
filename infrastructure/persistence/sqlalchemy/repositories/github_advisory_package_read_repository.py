from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any

from sqlalchemy import (
    and_,
    cast,
    exists,
    func,
    or_,
    select,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Session

from application.ports.outbound.github_advisory_package_read_repository import (
    GitHubAdvisoryPackageCandidate,
    GitHubAdvisoryPackageKey,
)
from infrastructure.persistence.models.normalized import (
    GitHubAdvisoryVulnerabilityModel,
)


class SqlAlchemyGitHubAdvisoryPackageReadRepository:
    """
    Lecture batch des packages affectés par GitHub Advisory.

    La requête filtre :
    - les advisories non retirés ;
    - l'écosystème ;
    - le nom de package normalisé.

    Aucune requête SQL n'est effectuée par package.
    """

    BATCH_SIZE = 200

    _PYPI_SEPARATOR_PATTERN = re.compile(
        r"[-_.]+"
    )

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
        normalized_keys = (
            self._normalize_keys(
                package_keys
            )
        )

        if not normalized_keys:
            return ()

        requested_keys = {
            (
                key.ecosystem,
                key.package_name,
            )
            for key in normalized_keys
        }

        candidates: list[
            GitHubAdvisoryPackageCandidate
        ] = []

        for batch in self._batches(
            normalized_keys
        ):
            statement = (
                self._build_statement(
                    batch
                )
            )

            rows = (
                self._session
                .execute(statement)
                .all()
            )

            for row in rows:
                (
                    ghsa_id,
                    cve_id,
                    severity,
                    affected_packages,
                ) = row

                candidates.extend(
                    self._candidates_from_row(
                        ghsa_id=ghsa_id,
                        cve_id=cve_id,
                        severity=severity,
                        affected_packages=(
                            affected_packages
                        ),
                        requested_keys=(
                            requested_keys
                        ),
                    )
                )

        return self._deduplicate_candidates(
            candidates
        )

    @classmethod
    def _normalize_keys(
        cls,
        package_keys: Iterable[
            GitHubAdvisoryPackageKey
        ],
    ) -> tuple[
        GitHubAdvisoryPackageKey,
        ...,
    ]:
        if isinstance(
            package_keys,
            (str, bytes),
        ):
            raise TypeError(
                "package_keys must be an iterable "
                "of GitHubAdvisoryPackageKey"
            )

        try:
            raw_keys = tuple(
                package_keys
            )
        except TypeError as error:
            raise TypeError(
                "package_keys must be iterable"
            ) from error

        unique: dict[
            tuple[str, str],
            GitHubAdvisoryPackageKey,
        ] = {}

        for key in raw_keys:
            if not isinstance(
                key,
                GitHubAdvisoryPackageKey,
            ):
                raise TypeError(
                    "Every package key must be a "
                    "GitHubAdvisoryPackageKey"
                )

            ecosystem = (
                cls._normalize_requested_ecosystem(
                    key.ecosystem
                )
            )

            package_name = (
                cls._normalize_package_name(
                    ecosystem=ecosystem,
                    package_name=(
                        key.package_name
                    ),
                )
            )

            normalized_key = (
                GitHubAdvisoryPackageKey(
                    ecosystem=ecosystem,
                    package_name=package_name,
                )
            )

            unique[
                (
                    ecosystem,
                    package_name,
                )
            ] = normalized_key

        return tuple(
            sorted(
                unique.values(),
                key=lambda key: (
                    key.ecosystem,
                    key.package_name,
                ),
            )
        )

    @classmethod
    def _build_statement(
        cls,
        package_keys: tuple[
            GitHubAdvisoryPackageKey,
            ...,
        ],
    ):
        affected_package = (
            func.jsonb_array_elements(
                GitHubAdvisoryVulnerabilityModel
                .affected_packages
            )
            .table_valued(
                "value"
            )
            .alias(
                "affected_package"
            )
        )

        package_json = cast(
            affected_package.c.value,
            JSONB,
        )

        ecosystem_expression = (
            func.lower(
                func.btrim(
                    package_json[
                        "ecosystem"
                    ].astext
                )
            )
        )

        raw_name_expression = (
            func.lower(
                func.btrim(
                    package_json[
                        "package_name"
                    ].astext
                )
            )
        )

        predicates = []

        for key in package_keys:
            if key.ecosystem == "pypi":
                name_expression = (
                    func.regexp_replace(
                        raw_name_expression,
                        r"[-_.]+",
                        "-",
                        "g",
                    )
                )

                ecosystem_predicate = (
                    ecosystem_expression.in_(
                        (
                            "pip",
                            "pypi",
                        )
                    )
                )

            else:
                name_expression = (
                    raw_name_expression
                )

                ecosystem_predicate = (
                    ecosystem_expression
                    == "npm"
                )

            predicates.append(
                and_(
                    ecosystem_predicate,
                    name_expression
                    == key.package_name,
                )
            )

        matching_package_exists = exists(
            select(1)
            .select_from(
                affected_package
            )
            .where(
                or_(
                    *predicates
                )
            )
        )

        return (
            select(
                GitHubAdvisoryVulnerabilityModel
                .ghsa_id,
                GitHubAdvisoryVulnerabilityModel
                .cve_id,
                GitHubAdvisoryVulnerabilityModel
                .severity,
                GitHubAdvisoryVulnerabilityModel
                .affected_packages,
            )
            .where(
                GitHubAdvisoryVulnerabilityModel
                .withdrawn_at
                .is_(None),
                matching_package_exists,
            )
        )

    @classmethod
    def _candidates_from_row(
        cls,
        *,
        ghsa_id: object,
        cve_id: object,
        severity: object,
        affected_packages: object,
        requested_keys: set[
            tuple[str, str]
        ],
    ) -> tuple[
        GitHubAdvisoryPackageCandidate,
        ...,
    ]:
        normalized_ghsa_id = (
            cls._optional_text(
                ghsa_id
            )
        )

        if normalized_ghsa_id is None:
            return ()

        normalized_cve_id = (
            cls._optional_text(
                cve_id
            )
        )

        normalized_severity = (
            cls._optional_text(
                severity
            )
        )

        if not isinstance(
            affected_packages,
            list,
        ):
            return ()

        candidates: list[
            GitHubAdvisoryPackageCandidate
        ] = []

        for package in affected_packages:
            if not isinstance(
                package,
                dict,
            ):
                continue

            candidate = (
                cls._candidate_from_package(
                    ghsa_id=(
                        normalized_ghsa_id
                    ),
                    cve_id=(
                        normalized_cve_id
                    ),
                    severity=(
                        normalized_severity
                    ),
                    package=package,
                    requested_keys=(
                        requested_keys
                    ),
                )
            )

            if candidate is not None:
                candidates.append(
                    candidate
                )

        return tuple(
            candidates
        )

    @classmethod
    def _candidate_from_package(
        cls,
        *,
        ghsa_id: str,
        cve_id: str | None,
        severity: str | None,
        package: dict[
            str,
            Any,
        ],
        requested_keys: set[
            tuple[str, str]
        ],
    ) -> (
        GitHubAdvisoryPackageCandidate
        | None
    ):
        raw_ecosystem = (
            cls._optional_text(
                package.get(
                    "ecosystem"
                )
            )
        )

        raw_package_name = (
            cls._optional_text(
                package.get(
                    "package_name"
                )
            )
        )

        vulnerable_version_range = (
            cls._optional_text(
                package.get(
                    "vulnerable_version_range"
                )
            )
        )

        if (
            raw_ecosystem is None
            or raw_package_name is None
            or vulnerable_version_range is None
        ):
            return None

        try:
            ecosystem = (
                cls._normalize_stored_ecosystem(
                    raw_ecosystem
                )
            )

            package_name = (
                cls._normalize_package_name(
                    ecosystem=ecosystem,
                    package_name=(
                        raw_package_name
                    ),
                )
            )
        except ValueError:
            return None

        if (
            ecosystem,
            package_name,
        ) not in requested_keys:
            return None

        first_patched_version = (
            cls._optional_text(
                package.get(
                    "first_patched_version"
                )
            )
        )

        return GitHubAdvisoryPackageCandidate(
            ghsa_id=ghsa_id,
            cve_id=cve_id,
            ecosystem=raw_ecosystem,
            package_name=(
                raw_package_name
            ),
            vulnerable_version_range=(
                vulnerable_version_range
            ),
            first_patched_version=(
                first_patched_version
            ),
            severity=severity,
        )

    @classmethod
    def _normalize_requested_ecosystem(
        cls,
        ecosystem: str,
    ) -> str:
        normalized = (
            cls._required_text(
                ecosystem,
                field_name="ecosystem",
            )
            .lower()
        )

        if normalized == "pip":
            return "pypi"

        if normalized in {
            "pypi",
            "npm",
        }:
            return normalized

        raise ValueError(
            "ecosystem must be one of: "
            "pypi, pip, npm"
        )

    @classmethod
    def _normalize_stored_ecosystem(
        cls,
        ecosystem: str,
    ) -> str:
        normalized = (
            ecosystem
            .strip()
            .lower()
        )

        if normalized in {
            "pip",
            "pypi",
        }:
            return "pypi"

        if normalized == "npm":
            return "npm"

        raise ValueError(
            "Unsupported stored ecosystem"
        )

    @classmethod
    def _normalize_package_name(
        cls,
        *,
        ecosystem: str,
        package_name: str,
    ) -> str:
        normalized = (
            cls._required_text(
                package_name,
                field_name="package_name",
            )
            .lower()
        )

        if ecosystem == "pypi":
            return (
                cls._PYPI_SEPARATOR_PATTERN
                .sub(
                    "-",
                    normalized,
                )
            )

        return normalized

    @staticmethod
    def _required_text(
        value: object,
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
        value: object,
    ) -> str | None:
        if not isinstance(
            value,
            str,
        ):
            return None

        normalized = value.strip()

        if not normalized:
            return None

        return normalized

    @classmethod
    def _batches(
        cls,
        values: tuple[
            GitHubAdvisoryPackageKey,
            ...,
        ],
    ):
        for index in range(
            0,
            len(values),
            cls.BATCH_SIZE,
        ):
            yield values[
                index:
                index + cls.BATCH_SIZE
            ]

    @staticmethod
    def _deduplicate_candidates(
        candidates: list[
            GitHubAdvisoryPackageCandidate
        ],
    ) -> tuple[
        GitHubAdvisoryPackageCandidate,
        ...,
    ]:
        unique: dict[
            tuple[
                str,
                str | None,
                str,
                str,
                str,
            ],
            GitHubAdvisoryPackageCandidate,
        ] = {}

        for candidate in candidates:
            key = (
                candidate.ghsa_id,
                candidate.cve_id,
                candidate.ecosystem,
                candidate.package_name,
                candidate.vulnerable_version_range,
            )

            unique.setdefault(
                key,
                candidate,
            )

        return tuple(
            sorted(
                unique.values(),
                key=lambda candidate: (
                    candidate.ecosystem,
                    candidate.package_name,
                    candidate.ghsa_id,
                    candidate.cve_id or "",
                    candidate.vulnerable_version_range,
                ),
            )
        )