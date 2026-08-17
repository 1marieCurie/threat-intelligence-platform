from __future__ import annotations

from unittest.mock import Mock
from uuid import uuid4

import pytest
from sqlalchemy.orm import Session

from application.ports.outbound.cisa_kev_application_read_repository import (
    CisaKevApplicationKey,
)
from infrastructure.persistence.sqlalchemy.repositories.cisa_kev_application_read_repository import (
    SqlAlchemyCisaKevApplicationReadRepository,
)
from infrastructure.persistence.sqlalchemy.repositories.vulnerability_exposure_repository import (
    SqlAlchemyVulnerabilityExposureRepository,
)


class FakeTupleResult:
    def __init__(
        self,
        rows,
    ) -> None:
        self._rows = rows

    def tuples(
        self,
    ):
        return self

    def all(
        self,
    ):
        return list(
            self._rows
        )


def _repository():
    session = Mock(
        spec=Session
    )

    repository = (
        SqlAlchemyCisaKevApplicationReadRepository(
            session=session
        )
    )

    return repository, session


def test_constructor_rejects_missing_session() -> None:
    with pytest.raises(
        ValueError,
        match="session must not be None",
    ):
        SqlAlchemyCisaKevApplicationReadRepository(
            session=None,  # type: ignore[arg-type]
        )


def test_empty_keys_do_not_query_database() -> None:
    repository, session = (
        _repository()
    )

    result = repository.find_candidates(
        application_keys=[]
    )

    assert result == ()

    session.execute.assert_not_called()


def test_reads_exact_vendor_product_candidate() -> None:
    repository, session = (
        _repository()
    )

    session.execute.return_value = (
        FakeTupleResult(
            [
                (
                    "CVE-2026-12345",
                    "Microsoft",
                    "Edge",
                )
            ]
        )
    )

    result = repository.find_candidates(
        application_keys=[
            CisaKevApplicationKey(
                vendor_project="microsoft",
                product="edge",
            )
        ]
    )

    assert len(result) == 1

    candidate = result[0]

    assert (
        candidate.cve_id
        == "CVE-2026-12345"
    )

    assert (
        candidate.vendor_project
        == "Microsoft"
    )

    assert (
        candidate.product
        == "Edge"
    )

    assert (
        candidate
        .normalized_vendor_project
        == "microsoft"
    )

    assert (
        candidate.normalized_product
        == "edge"
    )

    session.execute.assert_called_once()


def test_whitespace_and_case_are_normalized() -> None:
    repository, session = (
        _repository()
    )

    session.execute.return_value = (
        FakeTupleResult(
            [
                (
                    "cve-2026-12345",
                    "  MICROSOFT   ",
                    " Microsoft   Edge ",
                )
            ]
        )
    )

    result = repository.find_candidates(
        application_keys=[
            CisaKevApplicationKey(
                vendor_project="microsoft",
                product="microsoft edge",
            )
        ]
    )

    assert len(result) == 1

    assert (
        result[0].cve_id
        == "CVE-2026-12345"
    )


def test_non_matching_defensive_row_is_ignored() -> None:
    repository, session = (
        _repository()
    )

    session.execute.return_value = (
        FakeTupleResult(
            [
                (
                    "CVE-2026-12345",
                    "Microsoft",
                    "Windows",
                )
            ]
        )
    )

    result = repository.find_candidates(
        application_keys=[
            CisaKevApplicationKey(
                vendor_project="microsoft",
                product="edge",
            )
        ]
    )

    assert result == ()


def test_duplicate_candidate_is_deduplicated() -> None:
    repository, session = (
        _repository()
    )

    row = (
        "CVE-2026-12345",
        "Microsoft",
        "Edge",
    )

    session.execute.return_value = (
        FakeTupleResult(
            [
                row,
                row,
            ]
        )
    )

    result = repository.find_candidates(
        application_keys=[
            CisaKevApplicationKey(
                vendor_project="microsoft",
                product="edge",
            )
        ]
    )

    assert len(result) == 1


def test_duplicate_application_keys_are_deduplicated() -> None:
    repository, session = (
        _repository()
    )

    session.execute.return_value = (
        FakeTupleResult([])
    )

    repository.find_candidates(
        application_keys=[
            CisaKevApplicationKey(
                vendor_project="Microsoft",
                product="Edge",
            ),
            CisaKevApplicationKey(
                vendor_project=" microsoft ",
                product=" edge ",
            ),
        ]
    )

    session.execute.assert_called_once()


def test_invalid_application_key_type_is_rejected() -> None:
    repository, session = (
        _repository()
    )

    with pytest.raises(
        TypeError,
        match="CisaKevApplicationKey",
    ):
        repository.find_candidates(
            application_keys=[
                object(),  # type: ignore[list-item]
            ]
        )

    session.execute.assert_not_called()


def test_blank_lookup_value_is_rejected() -> None:
    repository, session = (
        _repository()
    )

    with pytest.raises(
        ValueError,
        match="must not be empty",
    ):
        repository.find_candidates(
            application_keys=[
                CisaKevApplicationKey(
                    vendor_project=" ",
                    product="Edge",
                )
            ]
        )

    session.execute.assert_not_called()
    
def test_set_kev_status_many_empty_input_returns_zero(
) -> None:
    session = Mock()

    repository = (
        SqlAlchemyVulnerabilityExposureRepository(
            session=session
        )
    )

    updated = (
        repository.set_kev_status_many(
            organization_id=uuid4(),
            machine_id=uuid4(),
            exposure_ids=(),
            is_kev=True,
        )
    )

    assert updated == 0

    session.execute.assert_not_called()
    
def test_set_kev_status_many_requires_boolean(
) -> None:
    repository = (
        SqlAlchemyVulnerabilityExposureRepository(
            session=Mock()
        )
    )

    with pytest.raises(
        TypeError,
        match="is_kev must be a bool",
    ):
        repository.set_kev_status_many(
            organization_id=uuid4(),
            machine_id=uuid4(),
            exposure_ids=(
                uuid4(),
            ),
            is_kev=1,  # type: ignore[arg-type]
        )
        
def test_set_kev_status_many_rejects_invalid_exposure_id(
) -> None:
    repository = (
        SqlAlchemyVulnerabilityExposureRepository(
            session=Mock()
        )
    )

    with pytest.raises(
        TypeError,
        match="Every exposure_id must be a UUID",
    ):
        repository.set_kev_status_many(
            organization_id=uuid4(),
            machine_id=uuid4(),
            exposure_ids=(
                "invalid",  # type: ignore[arg-type]
            ),
            is_kev=True,
        )