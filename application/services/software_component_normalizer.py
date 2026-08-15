from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass


@dataclass(
    frozen=True,
    slots=True,
)
class NormalizedSoftwareComponent:
    normalized_name: str
    normalized_vendor: str | None
    normalizer_version: str


class SoftwareComponentNormalizer:
    """
    Normalisation déterministe V1 des composants logiciels.

    Règles :
    - Unicode NFKC ;
    - trim ;
    - espaces consécutifs -> espace simple ;
    - lowercase ;
    - canonicalisation conservatrice des noms PyPI.

    Aucun fuzzy matching, alias implicite ou IA.
    """

    NORMALIZER_VERSION = "1.0.0"

    _WHITESPACE_PATTERN = re.compile(r"\s+")
    _PYPI_SEPARATOR_PATTERN = re.compile(r"[-_.]+")

    def normalize(
        self,
        *,
        component_type: str,
        name: str,
        vendor: str | None,
        ecosystem: str | None,
    ) -> NormalizedSoftwareComponent:
        normalized_component_type = (
            self._normalize_required_text(
                component_type,
                field_name="component_type",
            )
        )

        if normalized_component_type not in {
            "application",
            "package",
        }:
            raise ValueError(
                "component_type must be "
                "'application' or 'package'"
            )

        normalized_ecosystem = (
            None
            if ecosystem is None
            else self._normalize_required_text(
                ecosystem,
                field_name="ecosystem",
            )
        )

        if (
            normalized_component_type == "application"
            and normalized_ecosystem is not None
        ):
            raise ValueError(
                "application ecosystem must be None"
            )

        normalized_name = (
            self._normalize_required_text(
                name,
                field_name="name",
            )
        )

        if normalized_component_type == "package":
            normalized_name = (
                self._normalize_package_name(
                    name=normalized_name,
                    ecosystem=normalized_ecosystem,
                )
            )

        normalized_vendor = (
            None
            if vendor is None
            else self._normalize_required_text(
                vendor,
                field_name="vendor",
            )
        )

        return NormalizedSoftwareComponent(
            normalized_name=normalized_name,
            normalized_vendor=normalized_vendor,
            normalizer_version=self.NORMALIZER_VERSION,
        )

    @classmethod
    def _normalize_package_name(
        cls,
        *,
        name: str,
        ecosystem: str | None,
    ) -> str:
        if ecosystem == "pypi":
            return cls._PYPI_SEPARATOR_PATTERN.sub(
                "-",
                name,
            )

        if ecosystem == "npm":
            return name

        raise ValueError(
            "package ecosystem must be "
            "'pypi' or 'npm'"
        )

    @classmethod
    def _normalize_required_text(
        cls,
        value: str,
        *,
        field_name: str,
    ) -> str:
        if not isinstance(value, str):
            raise TypeError(
                f"{field_name} must be a string"
            )

        unicode_normalized = unicodedata.normalize(
            "NFKC",
            value,
        )

        whitespace_normalized = (
            cls._WHITESPACE_PATTERN.sub(
                " ",
                unicode_normalized.strip(),
            )
        )

        normalized = whitespace_normalized.lower()

        if not normalized:
            raise ValueError(
                f"{field_name} must not be empty"
            )

        return normalized