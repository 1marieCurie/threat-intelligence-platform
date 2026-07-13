#test the stability of domain object Threat after adding value object Indicator
from domain.indicator import Indicator
from domain.threat import Threat


def test_threat_defaults_are_backward_compatible() -> None:
    threat = Threat(id="CVE-2021-44228")

    assert threat.threat_type is None
    assert threat.source is None
    assert threat.indicators == []


def test_threat_accepts_phishing_indicators() -> None:
    threat = Threat(
        id="PHISHTANK-9477391",
        threat_type="phishing",
        source="PHISHTANK",
        indicators=[
            Indicator(
                type="url",
                value="https://example.invalid/login",
            ),
            Indicator(
                type="ipv4",
                value="192.0.2.10",
            ),
        ],
    )

    assert threat.threat_type == "phishing"
    assert threat.source == "PHISHTANK"
    assert len(threat.indicators) == 2


def test_threat_indicator_lists_are_not_shared() -> None:
    first = Threat(id="THREAT-1")
    second = Threat(id="THREAT-2")

    first.indicators.append(
        Indicator(
            type="ipv4",
            value="192.0.2.10",
        )
    )

    assert len(first.indicators) == 1
    assert second.indicators == []