from __future__ import annotations

from typing import Protocol

from application.models.url_analysis import (
    URLThreatClassification,
)
from application.models.url_features import (
    URLFeatureVector,
)


class URLThreatClassifierError(
    RuntimeError
):
    """
    Erreur générique du classifieur URL.
    """


class URLThreatClassifierConfigurationError(
    URLThreatClassifierError
):
    """
    Modèle, metadata ou configuration incompatibles.
    """


class URLThreatClassifierInferenceError(
    URLThreatClassifierError
):
    """
    Échec pendant une inférence.
    """


class URLThreatClassifier(
    Protocol
):
    """
    Port sortant du classifieur d'URL.

    La couche application ne connaît ni joblib,
    ni scikit-learn, ni le fichier modèle concret.
    """

    def classify(
        self,
        features: URLFeatureVector,
    ) -> URLThreatClassification:
        ...