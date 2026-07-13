import pytest

from domain.indicator import Indicator


def test_create_url_indicator() -> None:
    indicator = Indicator(
        type="url",
        value="https://example.invalid/login",
    )

    assert indicator.type == "url"
    assert indicator.value == "https://example.invalid/login"
    assert indicator.confidence is None
    assert indicator.metadata == {}


def test_indicator_normalizes_type_and_value() -> None:
    indicator = Indicator(
        type="  IPv4  ",
        value="  192.0.2.10  ",
    )

    assert indicator.type == "ipv4"
    assert indicator.value == "192.0.2.10"


@pytest.mark.parametrize(
    "indicator_type",
    ["", " ", "\t"],
)
def test_indicator_rejects_empty_type(
    indicator_type: str,
) -> None:
    with pytest.raises(
        ValueError,
        match="Indicator type must not be empty",
    ):
        Indicator(
            type=indicator_type,
            value="192.0.2.10",
        )


@pytest.mark.parametrize(
    "indicator_value",
    ["", " ", "\n"],
)
def test_indicator_rejects_empty_value(
    indicator_value: str,
) -> None:
    with pytest.raises(
        ValueError,
        match="Indicator value must not be empty",
    ):
        Indicator(
            type="ipv4",
            value=indicator_value,
        )


@pytest.mark.parametrize(
    "confidence",
    [-0.1, 1.1, 10.0],
)
def test_indicator_rejects_invalid_confidence(
    confidence: float,
) -> None:
    with pytest.raises(
        ValueError,
        match="confidence must be between",
    ):
        Indicator(
            type="url",
            value="https://example.invalid",
            confidence=confidence,
        )


def test_indicator_accepts_confidence_boundaries() -> None:
    minimum = Indicator(
        type="url",
        value="https://minimum.example.invalid",
        confidence=0.0,
    )

    maximum = Indicator(
        type="url",
        value="https://maximum.example.invalid",
        confidence=1.0,
    )

    assert minimum.confidence == 0.0
    assert maximum.confidence == 1.0


def test_indicator_preserves_metadata() -> None:
    indicator = Indicator(
        type="ipv4",
        value="192.0.2.10",
        metadata={
            "country": "MA",
            "rir": "afrinic",
        },
    )

    assert indicator.metadata["country"] == "MA"
    assert indicator.metadata["rir"] == "afrinic"