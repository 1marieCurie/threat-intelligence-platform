from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import Mock
from uuid import UUID, uuid4

import pytest
from sqlalchemy.orm import Session

from application.ports.outbound.urlhaus_url_repository import (
    URLhausBlacklistData,
    URLhausURLData,
)
from infrastructure.persistence.models import (
    Base,
    URLhausURLModel,
)
from infrastructure.persistence.sqlalchemy.repositories.urlhaus_url_repository import (
    SqlAlchemyURLhausURLRepository,
)


def _build_data(
) -> URLhausURLData:
    return URLhausURLData(
        raw_payload_id=uuid4(),
        urlhaus_id=3_886_372,
        malicious_url=(
            "http://59.180.140.134/"
            "malware"
        ),
        hostname="59.180.140.134",
        urlhaus_reference=(
            "https://urlhaus.abuse.ch/"
            "url/3886372/"
        ),
        url_status="online",
        date_added=datetime(
            2026,
            7,
            14,
            11,
            21,
            22,
            tzinfo=UTC,
        ),
        threat_type="malware_download",
        reporter="example-reporter",
        larted=True,
        tags=(
            "elf",
            "mips",
            "mozi",
        ),
        blacklists=(
            URLhausBlacklistData(
                name="spamhaus_dbl",
                status="not listed",
            ),
            URLhausBlacklistData(
                name="surbl",
                status="listed",
            ),
        ),
        normalizer_version="1.0.0",
    )


def test_model_is_registered_in_metadata(
) -> None:
    assert (
        "normalized.urlhaus_url"
        in Base.metadata.tables
    )


def test_save_adds_model_and_flushes(
) -> None:
    session = Mock(
        spec=Session,
    )

    repository = (
        SqlAlchemyURLhausURLRepository(
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

    model = (
        session.add.call_args.args[0]
    )

    assert isinstance(
        model,
        URLhausURLModel,
    )

    assert model.id == result

    assert (
        model.raw_payload_id
        == data.raw_payload_id
    )

    assert (
        model.urlhaus_id
        == 3_886_372
    )

    assert (
        model.malicious_url
        == data.malicious_url
    )

    assert (
        model.hostname
        == "59.180.140.134"
    )

    assert (
        model.url_status
        == "online"
    )

    assert (
        model.threat_type
        == "malware_download"
    )

    assert model.larted is True

    assert model.tags == [
        "elf",
        "mips",
        "mozi",
    ]

    assert model.blacklists == [
        {
            "name": "spamhaus_dbl",
            "status": "not listed",
        },
        {
            "name": "surbl",
            "status": "listed",
        },
    ]

    assert (
        model.normalizer_version
        == "1.0.0"
    )


def test_save_does_not_mutate_input_collections(
) -> None:
    session = Mock(
        spec=Session,
    )

    repository = (
        SqlAlchemyURLhausURLRepository(
            session=session,
        )
    )

    data = _build_data()

    original_tags = data.tags
    original_blacklists = (
        data.blacklists
    )

    repository.save(
        data
    )

    assert data.tags == original_tags

    assert (
        data.blacklists
        == original_blacklists
    )


def test_save_rejects_invalid_data(
) -> None:
    session = Mock(
        spec=Session,
    )

    repository = (
        SqlAlchemyURLhausURLRepository(
            session=session,
        )
    )

    with pytest.raises(
        TypeError,
        match=(
            "url_record must be "
            "a URLhausURLData"
        ),
    ):
        repository.save(
            object()  # type: ignore[arg-type]
        )

    session.add.assert_not_called()
    session.flush.assert_not_called()


def test_exists_returns_true_when_found(
) -> None:
    session = Mock(
        spec=Session,
    )

    session.execute.return_value \
        .scalar_one_or_none.return_value = (
            uuid4()
        )

    repository = (
        SqlAlchemyURLhausURLRepository(
            session=session,
        )
    )

    result = (
        repository
        .exists_by_raw_payload_id(
            uuid4()
        )
    )

    assert result is True

    session.execute.assert_called_once()


def test_exists_returns_false_when_missing(
) -> None:
    session = Mock(
        spec=Session,
    )

    session.execute.return_value \
        .scalar_one_or_none.return_value = (
            None
        )

    repository = (
        SqlAlchemyURLhausURLRepository(
            session=session,
        )
    )

    result = (
        repository
        .exists_by_raw_payload_id(
            uuid4()
        )
    )

    assert result is False


def test_exists_rejects_invalid_payload_id(
) -> None:
    session = Mock(
        spec=Session,
    )

    repository = (
        SqlAlchemyURLhausURLRepository(
            session=session,
        )
    )

    with pytest.raises(
        TypeError,
        match=(
            "raw_payload_id must be a UUID"
        ),
    ):
        repository.exists_by_raw_payload_id(
            "invalid"  # type: ignore[arg-type]
        )

    session.execute.assert_not_called()


def test_constructor_rejects_missing_session(
) -> None:
    with pytest.raises(
        ValueError,
        match="session must not be None",
    ):
        SqlAlchemyURLhausURLRepository(
            session=None,  # type: ignore[arg-type]
        )