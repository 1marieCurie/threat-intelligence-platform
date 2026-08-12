from __future__ import annotations

import math
from collections import Counter
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
    Extrait le Feature Set V1 depuis une URL
    déjà canonicalisée.

    Contraintes :
    - aucun réseau ;
    - aucun DNS ;
    - aucun WHOIS ;
    - aucun service externe ;
    - calcul déterministe ;
    - complexité O(n) sur la longueur de l'URL.

    Les features sont calculées sur l'URL canonique,
    avant toute projection privacy-safe.
    """

    VERSION = "2.0.0"

    MAX_URL_LENGTH = 4_096

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

            # Force la validation du port même si celui-ci
            # n'est plus une feature ML.
            _ = parsed.port

            hostname = parsed.hostname

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

        if not hostname:
            raise URLFeatureExtractionError(
                "canonical URL hostname is missing"
            )

        hostname = hostname.lower()

        path = (
            parsed.path
            or "/"
        )

        url_length = len(
            canonical_value
        )

        hostname_length = len(
            hostname
        )

        path_length = len(
            path
        )

        dot_count = (
            canonical_value.count(
                "."
            )
        )

        hyphen_count = (
            canonical_value.count(
                "-"
            )
        )

        digit_count = sum(
            character.isdigit()
            for character in canonical_value
        )

        # Important :
        # cette définition conserve exactement la
        # sémantique utilisée pendant l'EDA.
        special_char_count = sum(
            not character.isalnum()
            for character in canonical_value
        )

        path_segment_count = sum(
            1
            for segment in path.split(
                "/"
            )
            if segment
        )

        hostname_entropy = (
            self._shannon_entropy(
                hostname
            )
        )

        mean_hostname_label_length = (
            self._mean_hostname_label_length(
                hostname
            )
        )

        path_to_url_length_ratio = (
            path_length
            / url_length
        )

        special_char_ratio = (
            special_char_count
            / url_length
        )

        path_length_special_char_ratio_product = (
            self._normalized_product(
                path_length,
                special_char_ratio,
            )
        )

        path_segment_count_special_char_ratio_product = (
            self._normalized_product(
                path_segment_count,
                special_char_ratio,
            )
        )

        return URLFeatureVector(
            feature_set_version=(
                self.VERSION
            ),
            url_length=(
                url_length
            ),
            hostname_length=(
                hostname_length
            ),
            dot_count=(
                dot_count
            ),
            hyphen_count=(
                hyphen_count
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
            hostname_entropy=(
                hostname_entropy
            ),
            mean_hostname_label_length=(
                mean_hostname_label_length
            ),
            path_to_url_length_ratio=(
                path_to_url_length_ratio
            ),
            special_char_ratio=(
                special_char_ratio
            ),
            path_length_special_char_ratio_product=(
                path_length_special_char_ratio_product
            ),
            path_segment_count_special_char_ratio_product=(
                path_segment_count_special_char_ratio_product
            ),
        )

    @staticmethod
    def _shannon_entropy(
        value: str,
    ) -> float:
        if not value:
            return 0.0

        value_length = len(
            value
        )

        frequencies = Counter(
            value
        )

        return -sum(
            (
                count
                / value_length
            )
            * math.log2(
                count
                / value_length
            )
            for count in frequencies.values()
        )

    @staticmethod
    def _mean_hostname_label_length(
        hostname: str,
    ) -> float:
        labels = [
            label
            for label in hostname.split(
                "."
            )
            if label
        ]

        if not labels:
            return 0.0

        return (
            sum(
                len(label)
                for label in labels
            )
            / len(labels)
        )

    @staticmethod
    def _normalized_product(
        left: int | float,
        right: int | float,
    ) -> float:
        normalized_left = (
            left
            / (
                1.0
                + abs(left)
            )
        )

        normalized_right = (
            right
            / (
                1.0
                + abs(right)
            )
        )

        return (
            normalized_left
            * normalized_right
        )