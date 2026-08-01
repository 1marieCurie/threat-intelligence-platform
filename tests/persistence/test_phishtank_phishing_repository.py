from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import Mock
from uuid import UUID, uuid4

from sqlalchemy.orm import Session

from application.ports.outbound.phishtank_phishing_repository import (
    PhishTankNetworkDetailData,
    PhishTankPhishingData,
)
from infrastructure.persistence.models import (
    Base,
    PhishTankPhishingModel,
)
from infrastructure.persistence.sqlalchemy.repositories.phishtank_phishing_repository import (
    SqlAlchemyPhishTankPhishingRepository,
)


def _build_data() -> PhishTankPhishingData:
    return PhishTankPhishingData(
        raw_payload_id=uuid4(),
        phish_id=9477391,
        phishing_url=(
            "https://example.invalid/login"
        ),
        hostname="example.invalid",
        phish_detail_url=(
            "https://www.phishtank.com/"
            "phish_detail.php?"
            "phish_id=9477391"
        ),
        submission_time=datetime(
            2026,
            7,
            13,
            11,
            3,
            1,
            tzinfo=UTC,
        ),
        verification_time=datetime(
            2026,
            7,
            13,
            11,
            52,
            26,
            tzinfo=UTC,
        ),
        verified=True,
        online=True,
        target="Other",
        network_details=(
            PhishTankNetworkDetailData(
                ip_address="192.0.2.10",
                cidr_block="192.0.2.0/24",
                announcing_network="64500",
                rir="arin",
                country="MA",
                detail_time=datetime(
                    2026,
                    7,
                    13,
                    11,
                    12,
                    10,
                    tzinfo=UTC,
                ),
            ),
        ),
        normalizer_version="1.0.0",
    )


def test_model_is_registered_in_metadata() -> None:
    assert (
        "normalized.phishtank_phishing"
        in Base.metadata.tables
    )


def test_save_adds_model_and_flushes() -> None:
    session = Mock(
        spec=Session,
    )

    repository = (
        SqlAlchemyPhishTankPhishingRepository(
            session=session,
        )
    )

    data = _build_data()

    result = repository.save(
        data
    )

    assert isinstance(
        result,
        UUID,
    )

    session.add.assert_called_once()
    session.flush.assert_called_once_with()
    session.commit.assert_not_called()

    model = session.add.call_args.args[0]

    assert isinstance(
        model,
        PhishTankPhishingModel,
    )

    assert model.id == result
    assert (
        model.raw_payload_id
        == data.raw_payload_id
    )
    assert model.phish_id == 9477391
    assert (
        model.phishing_url
        == data.phishing_url
    )
    assert model.hostname == (
        "example.invalid"
    )
    assert model.verified is True
    assert model.online is True
    assert model.target == "Other"
    assert (
        model.normalizer_version
        == "1.0.0"
    )

    assert model.network_details == [
        {
            "ip_address": "192.0.2.10",
            "cidr_block": "192.0.2.0/24",
            "announcing_network": "64500",
            "rir": "arin",
            "country": "MA",
            "detail_time": (
                "2026-07-13T11:12:10+00:00"
            ),
        }
    ]


def test_exists_returns_true_when_found() -> None:
    session = Mock(
        spec=Session,
    )

    session.execute.return_value \
        .scalar_one_or_none.return_value = (
            uuid4()
        )

    repository = (
        SqlAlchemyPhishTankPhishingRepository(
            session=session,
        )
    )

    assert (
        repository
        .exists_by_raw_payload_id(
            uuid4()
        )
        is True
    )


def test_exists_returns_false_when_missing() -> None:
    session = Mock(
        spec=Session,
    )

    session.execute.return_value \
        .scalar_one_or_none.return_value = (
            None
        )

    repository = (
        SqlAlchemyPhishTankPhishingRepository(
            session=session,
        )
    )

    assert (
        repository
        .exists_by_raw_payload_id(
            uuid4()
        )
        is False
    )


def test_constructor_rejects_missing_session() -> None:
    try:
        SqlAlchemyPhishTankPhishingRepository(
            session=None,  # type: ignore[arg-type]
        )

    except ValueError as error:
        assert str(error) == (
            "session must not be None"
        )

    else:
        raise AssertionError(
            "Expected ValueError"
        )