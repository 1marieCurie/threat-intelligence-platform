from __future__ import annotations

from datetime import (
    UTC,
    datetime,
)
from uuid import uuid4

import pytest

from application.ports.outbound.cisa_kev_application_read_repository import (
    CisaKevApplicationCandidate,
)
from application.services.cisa_kev_application_matcher import (
    CisaKevApplicationMatcher,
)
from domain.software_component import (
    SoftwareComponent,
)


NOW = datetime(
    2026,
    8,
    17,
    12,
    0,
    tzinfo=UTC,
)


def _application(
    *,
    vendor: str | None = (
        "Microsoft Corporation"
    ),
    normalized_vendor: str | None = (
        "microsoft"
    ),
    name: str = "Microsoft Edge",
    normalized_name: str | None = (
        "microsoft edge"
    ),
    version: str | None = "140.0.0",
) -> SoftwareComponent:
    return SoftwareComponent(
        id=uuid4(),
        machine_id=uuid4(),
        component_type="application",
        name=name,
        normalized_name=(
            normalized_name
        ),
        version=version,
        vendor=vendor,
        normalized_vendor=(
            normalized_vendor
        ),
        ecosystem=None,
        external_id=(
            "HKLM64\\SOFTWARE\\"
            "Microsoft\\Windows\\"
            "CurrentVersion\\Uninstall\\"
            "Microsoft Edge"
        ),
        scope=None,
        detected_by=(
            "windows_registry_uninstall"
        ),
        created_at=NOW,
        updated_at=NOW,
    )


def _candidate(
    *,
    cve_id: str = (
        "CVE-2026-12345"
    ),
    vendor: str = "Microsoft",
    product: str = "Microsoft Edge",
    normalized_vendor: str = (
        "microsoft"
    ),
    normalized_product: str = (
        "microsoft edge"
    ),
) -> CisaKevApplicationCandidate:
    return CisaKevApplicationCandidate(
        cve_id=cve_id,
        vendor_project=vendor,
        product=product,
        normalized_vendor_project=(
            normalized_vendor
        ),
        normalized_product=(
            normalized_product
        ),
    )


def test_exact_vendor_product_creates_potential_kev_match(
) -> None:
    component = _application()

    matcher = (
        CisaKevApplicationMatcher()
    )

    matches = matcher.match(
        component=component,
        candidates=[
            _candidate()
        ],
    )

    assert len(matches) == 1

    match = matches[0]

    assert (
        match.software_component_id
        == component.id
    )

    assert (
        match.cve_id
        == "CVE-2026-12345"
    )

    assert (
        match.applicability_status
        == "potential"
    )

    assert (
        match.match_rule
        == (
            CisaKevApplicationMatcher
            .MATCH_RULE
        )
    )

    assert (
        match.match_version
        == component.version
    )

    assert match.is_kev is True


def test_vendor_mismatch_does_not_match(
) -> None:
    matcher = (
        CisaKevApplicationMatcher()
    )

    matches = matcher.match(
        component=_application(),
        candidates=[
            _candidate(
                normalized_vendor="google"
            )
        ],
    )

    assert matches == ()


def test_product_mismatch_does_not_match(
) -> None:
    matcher = (
        CisaKevApplicationMatcher()
    )

    matches = matcher.match(
        component=_application(),
        candidates=[
            _candidate(
                normalized_product=(
                    "windows"
                )
            )
        ],
    )

    assert matches == ()


def test_same_cve_is_deduplicated(
) -> None:
    matcher = (
        CisaKevApplicationMatcher()
    )

    candidate = _candidate()

    matches = matcher.match(
        component=_application(),
        candidates=[
            candidate,
            candidate,
        ],
    )

    assert len(matches) == 1


def test_multiple_cves_for_same_application_are_kept(
) -> None:
    matcher = (
        CisaKevApplicationMatcher()
    )

    matches = matcher.match(
        component=_application(),
        candidates=[
            _candidate(
                cve_id=(
                    "CVE-2026-12345"
                )
            ),
            _candidate(
                cve_id=(
                    "CVE-2026-12346"
                )
            ),
        ],
    )

    assert len(matches) == 2

    assert {
        match.cve_id
        for match in matches
    } == {
        "CVE-2026-12345",
        "CVE-2026-12346",
    }


def test_match_result_is_sorted_by_cve(
) -> None:
    matcher = (
        CisaKevApplicationMatcher()
    )

    matches = matcher.match(
        component=_application(),
        candidates=[
            _candidate(
                cve_id=(
                    "CVE-2026-20000"
                )
            ),
            _candidate(
                cve_id=(
                    "CVE-2026-10000"
                )
            ),
        ],
    )

    assert tuple(
        match.cve_id
        for match in matches
    ) == (
        "CVE-2026-10000",
        "CVE-2026-20000",
    )


def test_package_component_is_rejected(
) -> None:
    application = _application()

    package = SoftwareComponent(
        id=uuid4(),
        machine_id=(
            application.machine_id
        ),
        component_type="package",
        name="requests",
        normalized_name="requests",
        version="2.31.0",
        vendor=None,
        normalized_vendor=None,
        ecosystem="pypi",
        external_id=None,
        scope="global",
        detected_by="pip_global",
        created_at=NOW,
        updated_at=NOW,
    )

    matcher = (
        CisaKevApplicationMatcher()
    )

    with pytest.raises(
        ValueError,
        match="must be an application",
    ):
        matcher.match(
            component=package,
            candidates=[],
        )


def test_missing_normalized_vendor_is_rejected(
) -> None:
    component = _application(
        normalized_vendor=None
    )

    matcher = (
        CisaKevApplicationMatcher()
    )

    with pytest.raises(
        ValueError,
        match="normalized_vendor",
    ):
        matcher.match(
            component=component,
            candidates=[],
        )


def test_missing_normalized_name_is_rejected(
) -> None:
    component = _application(
        normalized_name=None
    )

    matcher = (
        CisaKevApplicationMatcher()
    )

    with pytest.raises(
        ValueError,
        match="normalized_name",
    ):
        matcher.match(
            component=component,
            candidates=[],
        )


def test_invalid_candidate_type_is_rejected(
) -> None:
    matcher = (
        CisaKevApplicationMatcher()
    )

    with pytest.raises(
        TypeError,
        match="CisaKevApplicationCandidate",
    ):
        matcher.match(
            component=_application(),
            candidates=[
                object(),  # type: ignore[list-item]
            ],
        )


def test_match_does_not_use_installed_version_to_confirm(
) -> None:
    component = _application(
        version="1.0.0"
    )

    matcher = (
        CisaKevApplicationMatcher()
    )

    matches = matcher.match(
        component=component,
        candidates=[
            _candidate()
        ],
    )

    assert len(matches) == 1

    match = matches[0]

    # La version est seulement enregistrée
    # comme contexte de matching.
    assert (
        match.match_version
        == "1.0.0"
    )

    # CISA KEV ne fournit pas ici de
    # version_range exploitable.
    assert (
        match.applicability_status
        == "potential"
    )


def test_empty_candidates_return_no_match(
) -> None:
    matcher = (
        CisaKevApplicationMatcher()
    )

    matches = matcher.match(
        component=_application(),
        candidates=[],
    )

    assert matches == ()