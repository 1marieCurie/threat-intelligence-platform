from __future__ import annotations

import hashlib
import json
from collections.abc import (
    Callable,
    Mapping,
)
from pathlib import Path
from typing import Any

from application.models.url_analysis import (
    URLThreatClassification,
)
from application.models.url_features import (
    URLFeatureVector,
)
from application.ports.outbound.url_threat_classifier import (
    URLThreatClassifierConfigurationError,
    URLThreatClassifierInferenceError,
)
from application.services.url_feature_extractor import (
    URLFeatureExtractor,
)


EXPECTED_CLASSES = frozenset(
    {
        "benign",
        "phishing",
        "malware",
    }
)


class JoblibURLThreatClassifier:
    """
    Adaptateur d'inférence pour le modèle URL
    scikit-learn sérialisé avec joblib.

    Responsabilités :
    - lire et valider le metadata ;
    - vérifier l'intégrité SHA-256 du modèle ;
    - vérifier le contrat des features ;
    - charger le modèle ;
    - extraire l'estimateur si l'artefact est un bundle ;
    - exécuter predict + predict_proba ;
    - retourner un résultat applicatif.

    Aucune URL brute ou canonique n'entre dans
    cet adaptateur : uniquement URLFeatureVector.
    """

    def __init__(
        self,
        *,
        model_path: str | Path,
        metadata_path: str | Path,
        model_loader: (
            Callable[[Path], Any] | None
        ) = None,
    ) -> None:
        self._model_path = Path(
            model_path
        )

        self._metadata_path = Path(
            metadata_path
        )

        if not self._model_path.is_file():
            raise (
                URLThreatClassifierConfigurationError(
                    "URL threat model file does not exist"
                )
            )

        if not self._metadata_path.is_file():
            raise (
                URLThreatClassifierConfigurationError(
                    "URL threat model metadata file "
                    "does not exist"
                )
            )

        metadata = self._load_metadata()

        (
            self._model_version,
            self._feature_set_version,
            self._feature_columns,
            expected_sha256,
        ) = self._validate_metadata(
            metadata
        )

        actual_sha256 = (
            self._compute_sha256(
                self._model_path
            )
        )

        if actual_sha256 != expected_sha256:
            raise (
                URLThreatClassifierConfigurationError(
                    "URL threat model integrity "
                    "check failed"
                )
            )

        loader = (
            self._default_model_loader
            if model_loader is None
            else model_loader
        )

        try:
            loaded_artifact = loader(
                self._model_path
            )

        except Exception as error:
            raise (
                URLThreatClassifierConfigurationError(
                    "URL threat model could not "
                    "be loaded"
                )
            ) from error

        self._model = (
            self._extract_model(
                loaded_artifact
            )
        )

        self._classes = (
            self._validate_model(
                self._model
            )
        )

    def classify(
        self,
        features: URLFeatureVector,
    ) -> URLThreatClassification:
        if not isinstance(
            features,
            URLFeatureVector,
        ):
            raise TypeError(
                "features must be URLFeatureVector"
            )

        if (
            features.feature_set_version
            != self._feature_set_version
        ):
            raise (
                URLThreatClassifierConfigurationError(
                    "URL feature vector version is "
                    "incompatible with the model"
                )
            )

        mapping = features.to_mapping()

        row = [
            mapping[column]
            for column
            in self._feature_columns
        ]

        batch = [
            row
        ]

        try:
            predictions = (
                self._model.predict(
                    batch
                )
            )

            probabilities = (
                self._model.predict_proba(
                    batch
                )
            )

        except Exception as error:
            raise (
                URLThreatClassifierInferenceError(
                    "URL threat model inference failed"
                )
            ) from error

        try:
            predicted_class = str(
                predictions[0]
            )

            if (
                predicted_class
                not in EXPECTED_CLASSES
            ):
                raise ValueError(
                    "unexpected predicted class"
                )

            class_index = (
                self._classes.index(
                    predicted_class
                )
            )

            confidence = float(
                probabilities[0][
                    class_index
                ]
            )

        except (
            IndexError,
            TypeError,
            ValueError,
        ) as error:
            raise (
                URLThreatClassifierInferenceError(
                    "URL threat model returned an "
                    "invalid prediction"
                )
            ) from error

        if not (
            0.0
            <= confidence
            <= 1.0
        ):
            raise (
                URLThreatClassifierInferenceError(
                    "URL threat model returned an "
                    "invalid probability"
                )
            )

        return URLThreatClassification(
            threat_class=predicted_class,  # pyright: ignore[reportArgumentType]
            confidence=confidence,
            model_version=(
                self._model_version
            ),
        )

    def _load_metadata(
        self,
    ) -> dict[str, Any]:
        try:
            raw_metadata = (
                self._metadata_path.read_text(
                    encoding="utf-8"
                )
            )

            metadata = json.loads(
                raw_metadata
            )

        except (
            OSError,
            UnicodeError,
            json.JSONDecodeError,
        ) as error:
            raise (
                URLThreatClassifierConfigurationError(
                    "URL threat model metadata "
                    "could not be read"
                )
            ) from error

        if not isinstance(
            metadata,
            dict,
        ):
            raise (
                URLThreatClassifierConfigurationError(
                    "URL threat model metadata "
                    "must be an object"
                )
            )

        return metadata

    @staticmethod
    def _validate_metadata(
        metadata: dict[str, Any],
    ) -> tuple[
        str,
        str,
        tuple[str, ...],
        str,
    ]:
        try:
            model_version = (
                metadata[
                    "model_version"
                ]
            )

            dataset = metadata[
                "dataset"
            ]

            features = metadata[
                "features"
            ]

            integrity = metadata[
                "integrity"
            ]

            feature_set_version = (
                dataset[
                    "feature_set_version"
                ]
            )

            feature_columns = (
                features[
                    "columns"
                ]
            )

            integrity_algorithm = (
                integrity[
                    "algorithm"
                ]
            )

            model_sha256 = (
                integrity[
                    "model_sha256"
                ]
            )

        except (
            KeyError,
            TypeError,
        ) as error:
            raise (
                URLThreatClassifierConfigurationError(
                    "URL threat model metadata "
                    "is incomplete"
                )
            ) from error

        if (
            not isinstance(
                model_version,
                str,
            )
            or not model_version.strip()
        ):
            raise (
                URLThreatClassifierConfigurationError(
                    "URL threat model version "
                    "is invalid"
                )
            )

        if (
            feature_set_version
            != URLFeatureExtractor.VERSION
        ):
            raise (
                URLThreatClassifierConfigurationError(
                    "URL threat model feature set "
                    "is incompatible with runtime"
                )
            )

        if (
            not isinstance(
                feature_columns,
                list,
            )
            or not all(
                isinstance(
                    column,
                    str,
                )
                for column
                in feature_columns
            )
        ):
            raise (
                URLThreatClassifierConfigurationError(
                    "URL threat model feature "
                    "columns are invalid"
                )
            )

        normalized_columns = tuple(
            feature_columns
        )

        if (
            normalized_columns
            != URLFeatureVector.FEATURE_NAMES
        ):
            raise (
                URLThreatClassifierConfigurationError(
                    "URL threat model feature "
                    "columns do not match runtime"
                )
            )

        if (
            not isinstance(
                integrity_algorithm,
                str,
            )
            or (
                integrity_algorithm.lower()
                != "sha256"
            )
        ):
            raise (
                URLThreatClassifierConfigurationError(
                    "URL threat model integrity "
                    "algorithm is unsupported"
                )
            )

        if (
            not isinstance(
                model_sha256,
                str,
            )
            or len(
                model_sha256
            )
            != 64
        ):
            raise (
                URLThreatClassifierConfigurationError(
                    "URL threat model SHA-256 "
                    "is invalid"
                )
            )

        return (
            model_version.strip(),
            feature_set_version,
            normalized_columns,
            model_sha256.lower(),
        )

    @staticmethod
    def _compute_sha256(
        path: Path,
    ) -> str:
        digest = hashlib.sha256()

        try:
            with path.open(
                "rb"
            ) as stream:
                while True:
                    chunk = stream.read(
                        1024 * 1024
                    )

                    if not chunk:
                        break

                    digest.update(
                        chunk
                    )

        except OSError as error:
            raise (
                URLThreatClassifierConfigurationError(
                    "URL threat model could not "
                    "be read"
                )
            ) from error

        return digest.hexdigest()

    @staticmethod
    def _default_model_loader(
        path: Path,
    ) -> Any:
        try:
            import joblib

        except ImportError as error:
            raise (
                URLThreatClassifierConfigurationError(
                    "joblib is required to load "
                    "the URL threat model"
                )
            ) from error

        return joblib.load(
            path
        )

    @classmethod
    def _extract_model(
        cls,
        artifact: Any,
    ) -> Any:
        """
        Extrait l'estimateur depuis l'artefact joblib.

        L'artefact peut être :
        - directement un modèle ;
        - un mapping contenant le modèle ;
        - un bundle contenant un unique objet compatible.
        """

        if cls._looks_like_model(
            artifact
        ):
            return artifact

        if isinstance(
            artifact,
            Mapping,
        ):
            for key in (
                "model",
                "estimator",
                "classifier",
                "pipeline",
            ):
                candidate = artifact.get(
                    key
                )

                if cls._looks_like_model(
                    candidate
                ):
                    return candidate

            candidates = [
                value
                for value
                in artifact.values()
                if cls._looks_like_model(
                    value
                )
            ]

            if len(
                candidates
            ) == 1:
                return candidates[0]

        raise (
            URLThreatClassifierConfigurationError(
                "URL threat artifact does not "
                "contain a compatible model"
            )
        )

    @staticmethod
    def _looks_like_model(
        candidate: Any,
    ) -> bool:
        if candidate is None:
            return False

        return (
            callable(
                getattr(
                    candidate,
                    "predict",
                    None,
                )
            )
            and callable(
                getattr(
                    candidate,
                    "predict_proba",
                    None,
                )
            )
        )

    @staticmethod
    def _validate_model(
        model: Any,
    ) -> tuple[str, ...]:
        if not callable(
            getattr(
                model,
                "predict",
                None,
            )
        ):
            raise (
                URLThreatClassifierConfigurationError(
                    "URL threat model does not "
                    "provide predict()"
                )
            )

        if not callable(
            getattr(
                model,
                "predict_proba",
                None,
            )
        ):
            raise (
                URLThreatClassifierConfigurationError(
                    "URL threat model does not "
                    "provide predict_proba()"
                )
            )

        raw_classes = getattr(
            model,
            "classes_",
            None,
        )

        if raw_classes is None:
            raise (
                URLThreatClassifierConfigurationError(
                    "URL threat model does not "
                    "provide classes_"
                )
            )

        try:
            classes = tuple(
                str(value)
                for value
                in raw_classes
            )

        except TypeError as error:
            raise (
                URLThreatClassifierConfigurationError(
                    "URL threat model classes "
                    "are invalid"
                )
            ) from error

        if (
            len(classes)
            != len(
                EXPECTED_CLASSES
            )
            or set(
                classes
            )
            != EXPECTED_CLASSES
        ):
            raise (
                URLThreatClassifierConfigurationError(
                    "URL threat model classes "
                    "do not match runtime"
                )
            )

        model_feature_names = getattr(
            model,
            "feature_names_in_",
            None,
        )

        if model_feature_names is not None:
            names = tuple(
                str(value)
                for value
                in model_feature_names
            )

            if (
                names
                != URLFeatureVector.FEATURE_NAMES
            ):
                raise (
                    URLThreatClassifierConfigurationError(
                        "URL threat model feature "
                        "names do not match runtime"
                    )
                )

        return classes