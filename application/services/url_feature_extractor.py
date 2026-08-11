from __future__ import annotations

import re
from ipaddress import ip_address
from urllib.parse import urlsplit

from application.models.url_features import (
    URLFeatureVector,
)


class URLFeatureExtractionError(
    ValueError
):
    """
    Erreur d'extraction des features.

    Le message ne doit jamais contenir
    l'URL traitée.
    """


class URLFeatureExtractor:
    """
    Extrait des features lexicales numériques
    depuis une URL déjà canonicalisée.

    Aucun réseau.
    Aucun DNS.
    Aucun WHOIS.
    Aucun service externe.

    L'extraction est déterministe et locale.
    """

    VERSION = "1.0.0"

    MAX_URL_LENGTH = 4_096

    _PERCENT_ENCODING_PATTERN = re.compile(
        r"%[0-9A-Fa-f]{2}"
    )

    def extract(
        self,
        canonical_value: str,
    ) -> URLFeatureVector:
        if not isinstance(
            canonical_value,
            str,
        ):
            raise TypeError(
                "canonical_value must be a string"
            )

        if not canonical_value:
            raise URLFeatureExtractionError(
                "canonical URL must not be empty"
            )

        if (
            len(canonical_value)
            > self.MAX_URL_LENGTH
        ):
            raise URLFeatureExtractionError(
                "canonical URL exceeds "
                f"{self.MAX_URL_LENGTH} characters"
            )

        try:
            parsed = urlsplit(
                canonical_value
            )

            port = parsed.port

        except (
            UnicodeError,
            ValueError,
        ) as error:
            raise URLFeatureExtractionError(
                "canonical URL is invalid"
            ) from error

        scheme = parsed.scheme.lower()

        if scheme not in {
            "http",
            "https",
        }:
            raise URLFeatureExtractionError(
                "canonical URL scheme is invalid"
            )

        hostname = parsed.hostname

        if not hostname:
            raise URLFeatureExtractionError(
                "canonical URL hostname is missing"
            )

        hostname = hostname.lower()

        path = (
            parsed.path
            or "/"
        )

        query = parsed.query
        fragment = parsed.fragment

        has_ip_address = (
            self._is_ip_address(
                hostname
            )
        )

        has_punycode = any(
            label.startswith(
                "xn--"
            )
            for label in hostname.split(
                "."
            )
        )

        path_segment_count = sum(
            1
            for segment in path.split(
                "/"
            )
            if segment
        )

        query_parameter_count = (
            0
            if not query
            else query.count("&") + 1
        )

        digit_count = sum(
            character.isdigit()
            for character in canonical_value
        )

        special_char_count = sum(
            not character.isalnum()
            for character in canonical_value
        )

        has_percent_encoding = bool(
            self._PERCENT_ENCODING_PATTERN.search(
                canonical_value
            )
        )

        return URLFeatureVector(
            feature_set_version=(
                self.VERSION
            ),
            url_length=len(
                canonical_value
            ),
            hostname_length=len(
                hostname
            ),
            path_length=len(
                path
            ),
            query_length=len(
                query
            ),
            fragment_length=len(
                fragment
            ),
            dot_count=(
                canonical_value.count(
                    "."
                )
            ),
            hyphen_count=(
                canonical_value.count(
                    "-"
                )
            ),
            digit_count=(
                digit_count
            ),
            special_char_count=(
                special_char_count
            ),
            path_segment_count=(
                path_segment_count
            ),
            query_parameter_count=(
                query_parameter_count
            ),
            has_ip_address=(
                has_ip_address
            ),
            has_https=(
                scheme == "https"
            ),
            has_non_default_port=(
                port is not None
            ),
            has_punycode=(
                has_punycode
            ),
            has_percent_encoding=(
                has_percent_encoding
            ),
        )

    @staticmethod
    def _is_ip_address(
        hostname: str,
    ) -> bool:
        try:
            ip_address(
                hostname
            )

        except ValueError:
            return False

        return True