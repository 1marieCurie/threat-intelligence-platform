from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar


URLFeatureValue = int | float


@dataclass(
    frozen=True,
    slots=True,
)
class URLFeatureVector:
    """
    Feature Set V1 lexical et structurel d'une URL canonique.

    Le vecteur contient uniquement les features validées
    pour le modèle ML V1.

    Aucune URL originale ou canonique n'est persistée ici.
    Les features identifiées comme source proxies pendant
    l'EDA ne font pas partie de ce contrat.
    """

    FEATURE_NAMES: ClassVar[
        tuple[str, ...]
    ] = (
        "url_length",
        "hostname_length",
        "dot_count",
        "hyphen_count",
        "digit_count",
        "special_char_count",
        "path_segment_count",
        "hostname_entropy",
        "mean_hostname_label_length",
        "path_to_url_length_ratio",
        "special_char_ratio",
        "path_length_special_char_ratio_product",
        "path_segment_count_special_char_ratio_product",
    )

    feature_set_version: str

    # Base features.
    url_length: int
    hostname_length: int
    dot_count: int
    hyphen_count: int
    digit_count: int
    special_char_count: int
    path_segment_count: int

    # Engineered features.
    hostname_entropy: float
    mean_hostname_label_length: float
    path_to_url_length_ratio: float
    special_char_ratio: float

    # Validated interactions.
    path_length_special_char_ratio_product: float
    path_segment_count_special_char_ratio_product: float

    def to_mapping(
        self,
    ) -> dict[
        str,
        URLFeatureValue,
    ]:
        """
        Retourne uniquement les features autorisées
        pour la persistance et l'entraînement.

        feature_set_version n'est volontairement pas
        dupliquée dans le document JSON.
        """

        return {
            feature_name: getattr(
                self,
                feature_name,
            )
            for feature_name
            in self.FEATURE_NAMES
        }