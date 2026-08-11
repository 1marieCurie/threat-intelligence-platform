from __future__ import annotations

from dataclasses import dataclass


@dataclass(
    frozen=True,
    slots=True,
)
class URLFeatureVector:
    """
    Features lexicales déterministes extraites
    depuis une URL canonique.

    Aucune URL originale ou canonique n'est persistée
    dans ce vecteur.
    """

    feature_set_version: str

    url_length: int
    hostname_length: int
    path_length: int
    query_length: int
    fragment_length: int

    dot_count: int
    hyphen_count: int
    digit_count: int
    special_char_count: int

    path_segment_count: int
    query_parameter_count: int

    has_ip_address: bool
    has_https: bool
    has_non_default_port: bool
    has_punycode: bool
    has_percent_encoding: bool