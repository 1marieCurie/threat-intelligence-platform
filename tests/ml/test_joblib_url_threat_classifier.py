from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from application.models.url_features import (
    URLFeatureVector,
)
from application.ports.outbound.url_threat_classifier import (
    URLThreatClassifierConfigurationError,
)
from application.services.url_feature_extractor import (
    URLFeatureExtractor,
)
from infrastructure.adapters.outbound.joblib_url_threat_classifier import (
    JoblibURLThreatClassifier,
)


class FakeModel:
    def __init__(
        self,
    ) -> None:
        # Ordre volontairement différent de l'ordre
        # métier pour vérifier qu'il n'est jamais
        # codé en dur.
        self.classes_ = (
            "malware",
            "benign",
            "phishing",
        )

        self.received_batch = None

    def predict(
        self,
        batch,
    ):
        self.received_batch = batch

        return [
            "phishing"
        ]

    def predict_proba(
        self,
        batch,
    ):
        self.received_batch = batch

        return [
            [
                0.08,
                0.12,
                0.80,
            ]
        ]


def _write_artifacts(
    tmp_path: Path,
    *,
    feature_set_version: str = "2.0.0",
    feature_columns: (
        list[str] | None
    ) = None,
    sha256_override: str | None = None,
) -> tuple[
    Path,
    Path,
]:
    model_path = (
        tmp_path
        / "model.joblib"
    )

    model_bytes = b"fake-model"

    model_path.write_bytes(
        model_bytes
    )

    actual_sha256 = (
        hashlib.sha256(
            model_bytes
        ).hexdigest()
    )

    metadata = {
        "model_version": (
            "test-hgb-v1"
        ),
        "dataset": {
            "feature_set_version": (
                feature_set_version
            ),
        },
        "features": {
            "columns": (
                list(
                    URLFeatureVector.FEATURE_NAMES
                )
                if feature_columns is None
                else feature_columns
            ),
        },
        "integrity": {
            "algorithm": "sha256",
            "model_sha256": (
                actual_sha256
                if sha256_override is None
                else sha256_override
            ),
        },
    }

    metadata_path = (
        tmp_path
        / "model.metadata.json"
    )

    metadata_path.write_text(
        json.dumps(
            metadata
        ),
        encoding="utf-8",
    )

    return (
        model_path,
        metadata_path,
    )


def _features(
):
    return (
        URLFeatureExtractor()
        .extract(
            "https://example.com/login"
        )
    )


def test_classifier_returns_real_model_class_and_probability(
    tmp_path: Path,
) -> None:
    (
        model_path,
        metadata_path,
    ) = _write_artifacts(
        tmp_path
    )

    model = FakeModel()

    classifier = (
        JoblibURLThreatClassifier(
            model_path=model_path,
            metadata_path=(
                metadata_path
            ),
            model_loader=(
                lambda _: model
            ),
        )
    )

    result = classifier.classify(
        _features()
    )

    assert (
        result.threat_class
        == "phishing"
    )

    assert (
        result.confidence
        == pytest.approx(
            0.80
        )
    )

    assert (
        result.model_version
        == "test-hgb-v1"
    )


def test_classifier_preserves_feature_column_order(
    tmp_path: Path,
) -> None:
    (
        model_path,
        metadata_path,
    ) = _write_artifacts(
        tmp_path
    )

    model = FakeModel()

    classifier = (
        JoblibURLThreatClassifier(
            model_path=model_path,
            metadata_path=(
                metadata_path
            ),
            model_loader=(
                lambda _: model
            ),
        )
    )

    features = _features()

    classifier.classify(
        features
    )

    expected_row = [
        features.to_mapping()[
            name
        ]
        for name
        in URLFeatureVector.FEATURE_NAMES
    ]

    assert (
        model.received_batch
        == [
            expected_row
        ]
    )


def test_classifier_rejects_modified_model_before_loading(
    tmp_path: Path,
) -> None:
    (
        model_path,
        metadata_path,
    ) = _write_artifacts(
        tmp_path,
        sha256_override=(
            "0" * 64
        ),
    )

    loader_called = False

    def loader(
        _,
    ):
        nonlocal loader_called

        loader_called = True

        return FakeModel()

    with pytest.raises(
        URLThreatClassifierConfigurationError,
        match="integrity",
    ):
        JoblibURLThreatClassifier(
            model_path=model_path,
            metadata_path=(
                metadata_path
            ),
            model_loader=loader,
        )

    assert loader_called is False


def test_classifier_rejects_feature_column_drift(
    tmp_path: Path,
) -> None:
    columns = list(
        URLFeatureVector.FEATURE_NAMES
    )

    columns.reverse()

    (
        model_path,
        metadata_path,
    ) = _write_artifacts(
        tmp_path,
        feature_columns=columns,
    )

    with pytest.raises(
        URLThreatClassifierConfigurationError,
        match="feature columns",
    ):
        JoblibURLThreatClassifier(
            model_path=model_path,
            metadata_path=(
                metadata_path
            ),
            model_loader=(
                lambda _: FakeModel()
            ),
        )


def test_classifier_rejects_feature_set_version_drift(
    tmp_path: Path,
) -> None:
    (
        model_path,
        metadata_path,
    ) = _write_artifacts(
        tmp_path,
        feature_set_version=(
            "999.0.0"
        ),
    )

    with pytest.raises(
        URLThreatClassifierConfigurationError,
        match="feature set",
    ):
        JoblibURLThreatClassifier(
            model_path=model_path,
            metadata_path=(
                metadata_path
            ),
            model_loader=(
                lambda _: FakeModel()
            ),
        )