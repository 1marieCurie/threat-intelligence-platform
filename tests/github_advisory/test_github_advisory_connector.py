from __future__ import annotations

from typing import Any

import pytest
import requests

from infrastructure.adapters.outbound.github_advisory_connector import (
    GitHubAdvisoryConnector,
    GitHubAdvisoryConnectorError,
)


# ============================================================
# Fake HTTP objects
# ============================================================


class FakeResponse(requests.Response):
    """
    Fake requests.Response used to test the connector
    without calling the real GitHub API.
    """

    def __init__(
        self,
        *,
        payload: Any = None,
        status_code: int = 200,
        links: dict[str, Any] | None = None,
        text: str = "",
        json_error: bool = False,
    ) -> None:
        super().__init__()

        self._payload = payload
        self.status_code = status_code
        self._fake_links = links or {}
        self._text_value = text
        self.json_error = json_error

    def json(self, **kwargs: Any) -> Any:
        if self.json_error:
            raise ValueError("Invalid JSON")

        return self._payload

    @property
    def links(self) -> dict[str, Any]:
        return self._fake_links

    @property
    def text(self) -> str:
        return self._text_value

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise requests.HTTPError(
                f"HTTP error {self.status_code}",
                response=self,
            )
            


class FakeSession(requests.Session):
    """
    Fake requests.Session.

    Each call to get() consumes one configured response.
    """

    def __init__(
        self,
        responses: list[requests.Response] | None = None,
        exception: requests.RequestException | None = None,
    ) -> None:
        super().__init__()

        self.responses = responses or []
        self.exception = exception
        self.calls: list[dict[str, Any]] = []

    def get(
        self,
        url: str,
        **kwargs: Any,
    ) -> requests.Response:
        self.calls.append(
            {
                "url": url,
                "headers": kwargs.get("headers"),
                "params": kwargs.get("params"),
                "timeout": kwargs.get("timeout"),
            }
        )

        if self.exception is not None:
            raise self.exception

        if not self.responses:
            raise AssertionError(
                "FakeSession has no configured response."
            )

        return self.responses.pop(0)


# ============================================================
# Fixtures
# ============================================================


@pytest.fixture
def sample_advisory() -> dict[str, Any]:
    return {
        "ghsa_id": "GHSA-jfh8-c2jp-5v3q",
        "cve_id": "CVE-2021-44228",
        "url": (
            "https://api.github.com/advisories/"
            "GHSA-jfh8-c2jp-5v3q"
        ),
        "html_url": (
            "https://github.com/advisories/"
            "GHSA-jfh8-c2jp-5v3q"
        ),
        "repository_advisory_url": None,
        "summary": "Log4Shell vulnerability",
        "description": "Remote code execution in Apache Log4j.",
        "type": "reviewed",
        "severity": "critical",
        "published_at": "2021-12-10T00:00:00Z",
        "updated_at": "2023-01-01T00:00:00Z",
        "github_reviewed_at": "2021-12-10T12:00:00Z",
        "nvd_published_at": "2021-12-10T10:15:00Z",
        "withdrawn_at": None,
        "identifiers": [
            {
                "value": "GHSA-jfh8-c2jp-5v3q",
                "type": "GHSA",
            },
            {
                "value": "CVE-2021-44228",
                "type": "CVE",
            },
        ],
        "vulnerabilities": [
            {
                "package": {
                    "ecosystem": "maven",
                    "name": (
                        "org.apache.logging.log4j:"
                        "log4j-core"
                    ),
                },
                "vulnerable_version_range": (
                    ">= 2.0-beta9, < 2.15.0"
                ),
                "first_patched_version": {
                    "identifier": "2.15.0",
                },
                "vulnerable_functions": [
                    (
                        "org.apache.logging.log4j.core."
                        "lookup.JndiLookup"
                    )
                ],
            }
        ],
        "cvss_severities": {
            "cvss_v3": {
                "vector_string": (
                    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/"
                    "S:C/C:H/I:H/A:H"
                ),
                "score": 10.0,
            },
            "cvss_v4": {
                "vector_string": (
                    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/"
                    "UI:N/VC:H/VI:H/VA:H"
                ),
                "score": 10.0,
            },
        },
        "epss": {
            "percentage": 0.94321,
            "percentile": 0.9999,
        },
        "cwes": [
            {
                "cwe_id": "CWE-502",
                "name": "Deserialization of Untrusted Data",
            }
        ],
        "references": [
            "https://logging.apache.org/log4j/"
        ],
        "source_code_location": (
            "https://github.com/apache/logging-log4j2"
        ),
    }
    
# ============================================================
# Initialization tests
# ============================================================


def test_unit_connector_initializes_without_token() -> None:
    connector = GitHubAdvisoryConnector()

    assert connector.timeout == 30.0
    assert "Authorization" not in connector.headers
    assert (
        connector.headers["Accept"]
        == "application/vnd.github+json"
    )
    assert (
        connector.headers["X-GitHub-Api-Version"]
        == "2022-11-28"
    )
    assert (
        connector.headers["User-Agent"]
        == "threat-intelligence-engine"
    )


def test_unit_connector_initializes_with_token() -> None:
    connector = GitHubAdvisoryConnector(
        token="github-test-token"
    )

    assert (
        connector.headers["Authorization"]
        == "Bearer github-test-token"
    )


@pytest.mark.parametrize(
    "timeout",
    [
        0,
        -1,
        -30.0,
    ],
)
def test_unit_connector_rejects_invalid_timeout(
    timeout: float,
) -> None:
    with pytest.raises(
        ValueError,
        match="timeout must be greater than zero",
    ):
        GitHubAdvisoryConnector(timeout=timeout)


# ============================================================
# Parameter construction tests
# ============================================================


def test_unit_build_params_with_default_values() -> None:
    params = GitHubAdvisoryConnector._build_params(
        ghsa_id=None,
        advisory_type="reviewed",
        cve_id=None,
        ecosystem=None,
        severity=None,
        cwes=None,
        is_withdrawn=None,
        affects=None,
        published=None,
        updated=None,
        modified=None,
        epss_percentage=None,
        epss_percentile=None,
        direction="desc",
        sort="published",
        per_page=30,
        before=None,
        after=None,
    )

    assert params == {
        "type": "reviewed",
        "direction": "desc",
        "sort": "published",
        "per_page": 30,
    }


def test_unit_build_params_with_all_filters() -> None:
    params = GitHubAdvisoryConnector._build_params(
        ghsa_id="GHSA-jfh8-c2jp-5v3q",
        advisory_type="reviewed",
        cve_id="CVE-2021-44228",
        ecosystem="maven",
        severity="critical",
        cwes=["CWE-502", 20],
        is_withdrawn=False,
        affects=[
            "org.apache.logging.log4j:log4j-core@2.14.1"
        ],
        published="2021-12-01..2021-12-31",
        updated=">=2022-01-01",
        modified="2021-12-01..2022-01-31",
        epss_percentage=">0.9",
        epss_percentile=">0.99",
        direction="asc",
        sort="updated",
        per_page=100,
        before="before-cursor",
        after="after-cursor",
    )

    assert params == {
        "ghsa_id": "GHSA-jfh8-c2jp-5v3q",
        "type": "reviewed",
        "cve_id": "CVE-2021-44228",
        "ecosystem": "maven",
        "severity": "critical",
        "cwes": "502,20",
        "is_withdrawn": "false",
        "affects": (
            "org.apache.logging.log4j:"
            "log4j-core@2.14.1"
        ),
        "published": "2021-12-01..2021-12-31",
        "updated": ">=2022-01-01",
        "modified": "2021-12-01..2022-01-31",
        "epss_percentage": ">0.9",
        "epss_percentile": ">0.99",
        "direction": "asc",
        "sort": "updated",
        "per_page": 100,
        "before": "before-cursor",
        "after": "after-cursor",
    }


@pytest.mark.parametrize(
    ("input_value", "expected"),
    [
        (79, "79"),
        ("79", "79"),
        ("CWE-79", "79"),
        ("cwe-79", "79"),
        ("  CWE-502  ", "502"),
    ],
)
def test_unit_normalize_cwe(
    input_value: str | int,
    expected: str,
) -> None:
    result = GitHubAdvisoryConnector._normalize_cwe(
        input_value
    )

    assert result == expected


@pytest.mark.parametrize(
    "invalid_cwe",
    [
        "",
        "CWE-",
        "CWE-ABC",
        "invalid",
        "79A",
    ],
)
def test_unit_normalize_cwe_rejects_invalid_values(
    invalid_cwe: str,
) -> None:
    with pytest.raises(
        ValueError,
        match="Invalid CWE identifier",
    ):
        GitHubAdvisoryConnector._normalize_cwe(
            invalid_cwe
        )


# ============================================================
# Parameter validation tests
# ============================================================


def test_unit_rejects_invalid_advisory_type() -> None:
    connector = GitHubAdvisoryConnector()

    with pytest.raises(
        ValueError,
        match="Invalid advisory_type",
    ):
        connector.fetch_advisories(
            advisory_type="invalid"
        )


def test_unit_rejects_invalid_ecosystem() -> None:
    connector = GitHubAdvisoryConnector()

    with pytest.raises(
        ValueError,
        match="Invalid ecosystem",
    ):
        connector.fetch_advisories(
            ecosystem="docker"
        )


def test_unit_rejects_invalid_severity() -> None:
    connector = GitHubAdvisoryConnector()

    with pytest.raises(
        ValueError,
        match="Invalid severity",
    ):
        connector.fetch_advisories(
            severity="extreme"
        )


def test_unit_rejects_invalid_direction() -> None:
    connector = GitHubAdvisoryConnector()

    with pytest.raises(
        ValueError,
        match="Invalid direction",
    ):
        connector.fetch_advisories(
            direction="up"
        )


def test_unit_rejects_invalid_sort_field() -> None:
    connector = GitHubAdvisoryConnector()

    with pytest.raises(
        ValueError,
        match="Invalid sort field",
    ):
        connector.fetch_advisories(
            sort="severity"
        )


@pytest.mark.parametrize(
    "per_page",
    [
        0,
        101,
        -1,
    ],
)
def test_unit_rejects_invalid_per_page(
    per_page: int,
) -> None:
    connector = GitHubAdvisoryConnector()

    with pytest.raises(
        ValueError,
        match="per_page must be between 1 and 100",
    ):
        connector.fetch_advisories(
            per_page=per_page
        )


@pytest.mark.parametrize(
    "max_pages",
    [
        0,
        -1,
    ],
)
def test_unit_rejects_invalid_max_pages(
    max_pages: int,
) -> None:
    connector = GitHubAdvisoryConnector()

    with pytest.raises(
        ValueError,
        match="max_pages must be greater",
    ):
        connector.fetch_advisories(
            max_pages=max_pages
        )


def test_unit_rejects_more_than_1000_affected_packages() -> None:
    connector = GitHubAdvisoryConnector()

    affects = [
        f"package-{index}"
        for index in range(1001)
    ]

    with pytest.raises(
        ValueError,
        match="affects cannot contain more than 1000",
    ):
        connector.fetch_advisories(
            affects=affects
        )


def test_unit_rejects_empty_affected_package_name() -> None:
    connector = GitHubAdvisoryConnector()

    with pytest.raises(
        ValueError,
        match="affects cannot contain empty",
    ):
        connector.fetch_advisories(
            affects=["requests", "   "]
        )


# ============================================================
# Main fetch tests
# ============================================================


def test_unit_fetch_advisories_returns_payload(
    sample_advisory: dict[str, Any],
) -> None:
    session = FakeSession(
        responses=[
            FakeResponse(
                payload=[sample_advisory]
            )
        ]
    )

    connector = GitHubAdvisoryConnector(
        session=session
    )

    result = connector.fetch_advisories(
        severity="critical",
        ecosystem="maven",
        per_page=10,
    )

    assert result == [sample_advisory]
    assert len(session.calls) == 1

    request = session.calls[0]

    assert (
        request["url"]
        == GitHubAdvisoryConnector.BASE_URL
    )
    assert request["timeout"] == 30.0

    assert request["params"] == {
        "type": "reviewed",
        "ecosystem": "maven",
        "severity": "critical",
        "direction": "desc",
        "sort": "published",
        "per_page": 10,
    }


def test_unit_fetch_advisories_returns_empty_list() -> None:
    session = FakeSession(
        responses=[
            FakeResponse(payload=[])
        ]
    )

    connector = GitHubAdvisoryConnector(
        session=session
    )

    result = connector.fetch_advisories()

    assert result == []


def test_unit_fetch_advisories_collects_multiple_pages(
    sample_advisory: dict[str, Any],
) -> None:
    first_advisory = sample_advisory

    second_advisory = {
        **sample_advisory,
        "ghsa_id": "GHSA-aaaa-bbbb-cccc",
        "cve_id": "CVE-2024-0001",
    }

    next_url = (
        "https://api.github.com/advisories"
        "?after=next-cursor"
    )

    session = FakeSession(
        responses=[
            FakeResponse(
                payload=[first_advisory],
                links={
                    "next": {
                        "url": next_url
                    }
                },
            ),
            FakeResponse(
                payload=[second_advisory]
            ),
        ]
    )

    connector = GitHubAdvisoryConnector(
        session=session
    )

    result = connector.fetch_advisories(
        max_pages=None
    )

    assert result == [
        first_advisory,
        second_advisory,
    ]

    assert len(session.calls) == 2

    first_request = session.calls[0]
    second_request = session.calls[1]

    assert first_request["params"] is not None
    assert second_request["url"] == next_url

    # GitHub's next URL already contains pagination params.
    assert second_request["params"] is None


def test_unit_fetch_advisories_respects_max_pages(
    sample_advisory: dict[str, Any],
) -> None:
    next_url = (
        "https://api.github.com/advisories"
        "?after=next-cursor"
    )

    session = FakeSession(
        responses=[
            FakeResponse(
                payload=[sample_advisory],
                links={
                    "next": {
                        "url": next_url
                    }
                },
            ),
            FakeResponse(
                payload=[
                    {
                        **sample_advisory,
                        "ghsa_id": "GHSA-page-2",
                    }
                ]
            ),
        ]
    )

    connector = GitHubAdvisoryConnector(
        session=session
    )

    result = connector.fetch_advisories(
        max_pages=1
    )

    assert result == [sample_advisory]
    assert len(session.calls) == 1


# ============================================================
# Specialized method tests
# ============================================================


def test_unit_fetch_advisory_by_ghsa_id(
    sample_advisory: dict[str, Any],
) -> None:
    session = FakeSession(
        responses=[
            FakeResponse(
                payload=[sample_advisory]
            )
        ]
    )

    connector = GitHubAdvisoryConnector(
        session=session
    )

    result = connector.fetch_advisory_by_ghsa_id(
        " GHSA-jfh8-c2jp-5v3q "
    )

    assert result == sample_advisory

    assert session.calls[0]["params"]["ghsa_id"] == (
        "GHSA-jfh8-c2jp-5v3q"
    )


def test_unit_fetch_advisory_by_ghsa_id_returns_none() -> None:
    session = FakeSession(
        responses=[
            FakeResponse(payload=[])
        ]
    )

    connector = GitHubAdvisoryConnector(
        session=session
    )

    result = connector.fetch_advisory_by_ghsa_id(
        "GHSA-aaaa-bbbb-cccc"
    )

    assert result is None


@pytest.mark.parametrize(
    "ghsa_id",
    [
        "",
        "   ",
    ],
)
def test_unit_fetch_advisory_by_ghsa_id_rejects_empty_id(
    ghsa_id: str,
) -> None:
    connector = GitHubAdvisoryConnector()

    with pytest.raises(
        ValueError,
        match="ghsa_id must not be empty",
    ):
        connector.fetch_advisory_by_ghsa_id(
            ghsa_id
        )


def test_unit_fetch_advisories_by_cve_id(
    sample_advisory: dict[str, Any],
) -> None:
    session = FakeSession(
        responses=[
            FakeResponse(
                payload=[sample_advisory]
            )
        ]
    )

    connector = GitHubAdvisoryConnector(
        session=session
    )

    result = connector.fetch_advisories_by_cve_id(
        " CVE-2021-44228 "
    )

    assert result == [sample_advisory]

    assert session.calls[0]["params"]["cve_id"] == (
        "CVE-2021-44228"
    )


@pytest.mark.parametrize(
    "cve_id",
    [
        "",
        "   ",
    ],
)
def test_unit_fetch_advisories_by_cve_id_rejects_empty_id(
    cve_id: str,
) -> None:
    connector = GitHubAdvisoryConnector()

    with pytest.raises(
        ValueError,
        match="cve_id must not be empty",
    ):
        connector.fetch_advisories_by_cve_id(
            cve_id
        )


def test_unit_fetch_modified_advisories(
    sample_advisory: dict[str, Any],
) -> None:
    session = FakeSession(
        responses=[
            FakeResponse(
                payload=[sample_advisory]
            )
        ]
    )

    connector = GitHubAdvisoryConnector(
        session=session
    )

    result = connector.fetch_modified_advisories(
        " 2026-07-01..2026-07-10 ",
        per_page=50,
        max_pages=1,
    )

    assert result == [sample_advisory]

    params = session.calls[0]["params"]

    assert params["modified"] == (
        "2026-07-01..2026-07-10"
    )
    assert params["sort"] == "updated"
    assert params["direction"] == "asc"
    assert params["per_page"] == 50


@pytest.mark.parametrize(
    "modified",
    [
        "",
        "   ",
    ],
)
def test_unit_fetch_modified_advisories_rejects_empty_range(
    modified: str,
) -> None:
    connector = GitHubAdvisoryConnector()

    with pytest.raises(
        ValueError,
        match="modified must not be empty",
    ):
        connector.fetch_modified_advisories(
            modified
        )


# ============================================================
# Error handling tests
# ============================================================


def test_unit_timeout_is_converted_to_connector_error() -> None:
    session = FakeSession(
        exception=requests.Timeout()
    )

    connector = GitHubAdvisoryConnector(
        session=session
    )

    with pytest.raises(
        GitHubAdvisoryConnectorError,
        match="timed out",
    ):
        connector.fetch_advisories()


def test_unit_request_error_is_converted_to_connector_error() -> None:
    session = FakeSession(
        exception=requests.ConnectionError(
            "Connection refused"
        )
    )

    connector = GitHubAdvisoryConnector(
        session=session
    )

    with pytest.raises(
        GitHubAdvisoryConnectorError,
        match="Unable to contact",
    ):
        connector.fetch_advisories()


def test_unit_http_error_contains_github_message() -> None:
    session = FakeSession(
        responses=[
            FakeResponse(
                payload={
                    "message": "API rate limit exceeded"
                },
                status_code=403,
            )
        ]
    )

    connector = GitHubAdvisoryConnector(
        session=session
    )

    with pytest.raises(
        GitHubAdvisoryConnectorError,
        match="API rate limit exceeded",
    ):
        connector.fetch_advisories()


def test_unit_invalid_json_raises_connector_error() -> None:
    session = FakeSession(
        responses=[
            FakeResponse(
                json_error=True
            )
        ]
    )

    connector = GitHubAdvisoryConnector(
        session=session
    )

    with pytest.raises(
        GitHubAdvisoryConnectorError,
        match="returned invalid JSON",
    ):
        connector.fetch_advisories()


def test_unit_dictionary_payload_is_rejected() -> None:
    session = FakeSession(
        responses=[
            FakeResponse(
                payload={
                    "ghsa_id": "GHSA-test"
                }
            )
        ]
    )

    connector = GitHubAdvisoryConnector(
        session=session
    )

    with pytest.raises(
        GitHubAdvisoryConnectorError,
        match="a JSON array was expected",
    ):
        connector.fetch_advisories()


def test_unit_non_dictionary_items_are_rejected() -> None:
    session = FakeSession(
        responses=[
            FakeResponse(
                payload=[
                    "invalid advisory",
                    123,
                ]
            )
        ]
    )

    connector = GitHubAdvisoryConnector(
        session=session
    )

    with pytest.raises(
        GitHubAdvisoryConnectorError,
        match="every advisory must be a JSON object",
    ):
        connector.fetch_advisories()


# ============================================================
# Integration tests
# ============================================================


@pytest.mark.integration
def test_integration_fetch_latest_reviewed_advisories() -> None:
    """
    Calls the real GitHub API.

    This test requires internet access. Authentication is optional.
    """

    connector = GitHubAdvisoryConnector(
        timeout=30.0
    )

    advisories = connector.fetch_advisories(
        advisory_type="reviewed",
        per_page=5,
        max_pages=1,
    )

    print(
        "\n[GITHUB ADVISORY INTEGRATION] "
        "Latest reviewed advisories"
    )
    print(f"Collected advisories: {len(advisories)}")

    assert isinstance(advisories, list)
    assert len(advisories) <= 5

    for advisory in advisories:
        assert isinstance(advisory, dict)
        assert "ghsa_id" in advisory

        print(
            f"- {advisory.get('ghsa_id')} | "
            f"{advisory.get('cve_id')} | "
            f"{advisory.get('severity')} | "
            f"{advisory.get('summary')}"
        )


@pytest.mark.integration
def test_integration_fetch_advisory_by_known_cve() -> None:
    """
    Checks a well-known CVE that should be present
    in GitHub's Advisory Database.
    """

    connector = GitHubAdvisoryConnector(
        timeout=30.0
    )

    advisories = connector.fetch_advisories_by_cve_id(
        "CVE-2021-44228"
    )

    print(
        "\n[GITHUB ADVISORY INTEGRATION] "
        "Search by CVE"
    )
    print(f"Matching advisories: {len(advisories)}")

    assert isinstance(advisories, list)
    assert len(advisories) >= 1

    first = advisories[0]

    assert first.get("cve_id") == "CVE-2021-44228"
    assert first.get("ghsa_id") is not None

    print(f"GHSA ID     : {first.get('ghsa_id')}")
    print(f"CVE ID      : {first.get('cve_id')}")
    print(f"Severity    : {first.get('severity')}")
    print(f"Summary     : {first.get('summary')}")
    print(f"Published   : {first.get('published_at')}")
    print(f"Updated     : {first.get('updated_at')}")


@pytest.mark.integration
def test_integration_fetch_critical_maven_advisories() -> None:
    connector = GitHubAdvisoryConnector(
        timeout=30.0
    )

    advisories = connector.fetch_advisories(
        ecosystem="maven",
        severity="critical",
        per_page=5,
        max_pages=1,
    )

    print(
        "\n[GITHUB ADVISORY INTEGRATION] "
        "Critical Maven advisories"
    )
    print(f"Collected advisories: {len(advisories)}")

    assert isinstance(advisories, list)

    for advisory in advisories:
        assert advisory.get("severity") == "critical"

        print(
            f"- {advisory.get('ghsa_id')} | "
            f"{advisory.get('cve_id')} | "
            f"{advisory.get('summary')}"
        )

def test_fetch_advisory_page_returns_records_and_next_cursor(
    sample_advisory: dict[str, Any],
) -> None:
    response = FakeResponse(
        payload=[sample_advisory],
        links={
            "next": {
                "url": (
                    "https://api.github.com/advisories"
                    "?type=reviewed"
                    "&per_page=100"
                    "&after=cursor-page-2"
                ),
            },
        },
    )

    session = FakeSession(
        responses=[response],
    )

    connector = GitHubAdvisoryConnector(
        session=session,
    )

    page = connector.fetch_advisory_page(
        after="cursor-page-1",
        per_page=100,
    )

    assert page.advisories == [
        sample_advisory,
    ]
    assert page.next_cursor == "cursor-page-2"

    assert len(session.calls) == 1

    request_params = session.calls[0]["params"]

    assert request_params["after"] == "cursor-page-1"
    assert request_params["sort"] == "updated"
    assert request_params["direction"] == "asc"
    assert request_params["per_page"] == 100

def test_fetch_advisory_page_returns_none_without_next_page(
    sample_advisory: dict[str, Any],
) -> None:
    response = FakeResponse(
        payload=[sample_advisory],
        links={},
    )

    session = FakeSession(
        responses=[response],
    )

    connector = GitHubAdvisoryConnector(
        session=session,
    )

    page = connector.fetch_advisory_page()

    assert page.advisories == [
        sample_advisory,
    ]
    assert page.next_cursor is None

def test_extract_cursor_returns_none_for_invalid_link() -> None:
    assert (
        GitHubAdvisoryConnector._extract_cursor(
            url=(
                "https://api.github.com/advisories"
                "?per_page=100"
            ),
            parameter="after",
        )
        is None
    )