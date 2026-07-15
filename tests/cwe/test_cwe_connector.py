# tests/cwe/test_cwe_connector.py

from __future__ import annotations

from typing import Any, Callable

import pytest
import requests

from infrastructure.adapters.outbound.cwe_connector import (
    CWEConnector,
)


# ============================================================
# Fake HTTP response
# ============================================================


class FakeResponse:
    """
    Minimal replacement for requests.Response.

    Supported behavior:
    - status_code;
    - json();
    - raise_for_status().
    """

    def __init__(
        self,
        *,
        json_data: Any = None,
        status_code: int = 200,
        json_error: Exception | None = None,
    ) -> None:
        self._json_data = json_data
        self.status_code = status_code
        self._json_error = json_error

    def json(self) -> Any:
        if self._json_error is not None:
            raise self._json_error

        return self._json_data

    def raise_for_status(self) -> None:
        if self.status_code < 400:
            return

        response = requests.Response()

        object.__setattr__(
            response,
            "status_code",
            self.status_code,
        )

        raise requests.HTTPError(
            f"HTTP {self.status_code}",
            response=response,
        )


# ============================================================
# Fake HTTP session
# ============================================================


class FakeSession:
    """
    Deterministic requests.Session replacement.

    Responses are returned in their configured order.
    """

    def __init__(
        self,
        responses: list[FakeResponse] | None = None,
    ) -> None:
        self.responses = list(
            responses or []
        )

        self.headers: dict[str, str] = {}

        self.calls: list[
            dict[str, Any]
        ] = []

    def get(
        self,
        url: str,
        *,
        params: dict[str, Any] | None = None,
        timeout: int | float | None = None,
    ) -> FakeResponse:
        self.calls.append(
            {
                "url": url,
                "params": params,
                "timeout": timeout,
            }
        )

        if not self.responses:
            raise AssertionError(
                "No fake response configured."
            )

        return self.responses.pop(0)


ConnectorFactory = Callable[
    [
        list[FakeResponse],
    ],
    tuple[CWEConnector, FakeSession],
]


# ============================================================
# Fixtures
# ============================================================


@pytest.fixture
def version_payload() -> dict[str, Any]:
    """
    Representative GET /cwe/version response.
    """

    return {
        "ContentVersion": "4.20",
        "ContentDate": "2026-04-30",
        "TotalWeaknesses": 969,
        "TotalCategories": 422,
        "TotalViews": 59,
    }


@pytest.fixture
def cwe_79_payload() -> dict[str, Any]:
    """
    Representative CWE-79 response.
    """

    return {
        "Weaknesses": [
            {
                "ID": "79",
                "Name": (
                    "Improper Neutralization of Input "
                    "During Web Page Generation "
                    "('Cross-site Scripting')"
                ),
                "Abstraction": "Base",
                "Structure": "Simple",
                "Status": "Stable",
                "Description": (
                    "The product does not neutralize or "
                    "incorrectly neutralizes user-controllable "
                    "input before it is placed in output that "
                    "is used as a web page."
                ),
                "ExtendedDescription": (
                    "Cross-site scripting vulnerabilities occur "
                    "when untrusted input is included in web "
                    "content without proper neutralization."
                ),
                "LikelihoodOfExploit": "High",
                "RelatedWeaknesses": [
                    {
                        "Nature": "ChildOf",
                        "CweID": "74",
                        "ViewID": "1000",
                    }
                ],
                "CommonConsequences": [
                    {
                        "Scope": [
                            "Confidentiality",
                            "Integrity",
                        ],
                        "Impact": [
                            "Read Application Data",
                            "Modify Application Data",
                        ],
                    }
                ],
                "PotentialMitigations": [
                    {
                        "Phase": [
                            "Implementation",
                        ],
                        "Description": (
                            "Encode output according to the "
                            "target context."
                        ),
                    }
                ],
                "DetectionMethods": [
                    {
                        "Method": "Automated Static Analysis",
                        "Description": (
                            "Use static analysis to detect "
                            "potentially unsafe output."
                        ),
                    }
                ],
                "ApplicablePlatforms": {
                    "Languages": [
                        {
                            "Name": "JavaScript",
                            "Prevalence": "Often",
                        }
                    ]
                },
                "ModesOfIntroduction": [
                    {
                        "Phase": "Implementation",
                    }
                ],
                "AlternateTerms": [
                    {
                        "Term": "XSS",
                    }
                ],
            }
        ],
    }


@pytest.fixture
def multiple_cwes_payload() -> dict[str, Any]:
    """
    Representative multi-CWE response.
    """

    return {
        "Weaknesses": [
            {
                "ID": "79",
                "Name": "Cross-site Scripting",
                "Description": (
                    "Example CWE-79 description."
                ),
            },
            {
                "ID": "89",
                "Name": "SQL Injection",
                "Description": (
                    "Example CWE-89 description."
                ),
            },
            {
                "ID": "502",
                "Name": (
                    "Deserialization of Untrusted Data"
                ),
                "Description": (
                    "Example CWE-502 description."
                ),
            },
        ],
    }


@pytest.fixture
def connector_factory():
    """
    Build a CWEConnector with a FakeSession.
    """

    def _factory(
        responses: list[FakeResponse],
        *,
        timeout: int | float = 30,
    ) -> tuple[CWEConnector, FakeSession]:
        session = FakeSession(
            responses=responses
        )

        connector = CWEConnector(
            session=session,  # type: ignore[arg-type]
            timeout=timeout,
        )

        return connector, session

    return _factory


# ============================================================
# Constructor tests
# ============================================================


def test_unit_constructor_sets_default_headers(
    connector_factory,
) -> None:
    connector, session = connector_factory([])

    assert connector.session is session

    assert session.headers["Accept"] == (
        "application/json"
    )

    assert session.headers["User-Agent"] == (
        "Threat-Intelligence-Engine/1.0"
    )


@pytest.mark.parametrize(
    "timeout",
    [
        0,
        -1,
        -10.5,
        True,
        False,
    ],
)
def test_unit_constructor_rejects_invalid_timeout_values(
    timeout: Any,
) -> None:
    with pytest.raises(
        ValueError,
        match="timeout must be greater than zero",
    ):
        CWEConnector(
            session=FakeSession(),  # type: ignore[arg-type]
            timeout=timeout,
        )


@pytest.mark.parametrize(
    "timeout",
    [
        None,
        "30",
        [],
        {},
    ],
)
def test_unit_constructor_rejects_invalid_timeout_types(
    timeout: Any,
) -> None:
    with pytest.raises(
        TypeError,
        match="timeout must be an integer or float",
    ):
        CWEConnector(
            session=FakeSession(),  # type: ignore[arg-type]
            timeout=timeout,
        )


def test_unit_constructor_accepts_float_timeout(
    connector_factory,
) -> None:
    connector, _ = connector_factory(
        [],
        timeout=5.5,
    )

    assert connector.timeout == 5.5


# ============================================================
# Version tests
# ============================================================


def test_unit_fetch_version(
    connector_factory,
    version_payload: dict[str, Any],
) -> None:
    connector, session = connector_factory(
        [
            FakeResponse(
                json_data=version_payload
            )
        ]
    )

    result = connector.fetch_version()

    assert result == version_payload
    assert len(session.calls) == 1

    call = session.calls[0]

    assert call["url"] == (
        "https://cwe-api.mitre.org/api/v1/"
        "cwe/version"
    )

    assert call["params"] is None
    assert call["timeout"] == 30


@pytest.mark.parametrize(
    "invalid_payload",
    [
        None,
        [],
        "invalid",
        123,
    ],
)
def test_unit_fetch_version_rejects_invalid_payload(
    connector_factory,
    invalid_payload: Any,
) -> None:
    connector, _ = connector_factory(
        [
            FakeResponse(
                json_data=invalid_payload
            )
        ]
    )

    with pytest.raises(
        ValueError,
        match="Invalid CWE version response",
    ):
        connector.fetch_version()


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {
            "Weaknesses": None,
        },
        {
            "Weaknesses": {},
        },
    ],
)
def test_unit_fetch_version_accepts_any_json_object(
    connector_factory,
    payload: dict[str, Any],
) -> None:
    """
    The connector currently validates only that the version
    endpoint returns a JSON object.

    Detailed validation of ContentVersion, ContentDate and totals
    belongs to the catalog service.
    """

    connector, _ = connector_factory(
        [
            FakeResponse(
                json_data=payload
            )
        ]
    )

    assert connector.fetch_version() == payload


# ============================================================
# Single weakness tests
# ============================================================


def test_unit_fetch_single_weakness_with_canonical_id(
    connector_factory,
    cwe_79_payload: dict[str, Any],
) -> None:
    connector, session = connector_factory(
        [
            FakeResponse(
                json_data=cwe_79_payload
            )
        ]
    )

    result = connector.fetch_weakness(
        "CWE-79"
    )

    assert result == cwe_79_payload

    assert session.calls[0]["url"] == (
        "https://cwe-api.mitre.org/api/v1/"
        "cwe/weakness/79"
    )


@pytest.mark.parametrize(
    "identifier",
    [
        "CWE-79",
        "cwe-79",
        "79",
        79,
        " CWE-79 ",
        "00079",
        "CWE-00079",
    ],
)
def test_unit_fetch_single_weakness_normalizes_id(
    connector_factory,
    cwe_79_payload: dict[str, Any],
    identifier: str | int,
) -> None:
    connector, session = connector_factory(
        [
            FakeResponse(
                json_data=cwe_79_payload
            )
        ]
    )

    connector.fetch_weakness(identifier)

    assert session.calls[0]["url"].endswith(
        "/cwe/weakness/79"
    )


def test_unit_fetch_single_weakness_rejects_empty_result(
    connector_factory,
) -> None:
    connector, _ = connector_factory(
        [
            FakeResponse(
                json_data={
                    "Weaknesses": [],
                }
            )
        ]
    )

    with pytest.raises(
        ValueError,
        match="CWE-79 was not returned",
    ):
        connector.fetch_weakness(
            "CWE-79"
        )


# ============================================================
# Complete catalog tests
# ============================================================


def test_unit_fetch_all_weaknesses(
    connector_factory,
    multiple_cwes_payload: dict[str, Any],
) -> None:
    connector, session = connector_factory(
        [
            FakeResponse(
                json_data=multiple_cwes_payload
            )
        ]
    )

    result = connector.fetch_all_weaknesses()

    assert result == multiple_cwes_payload
    assert len(session.calls) == 1

    assert session.calls[0]["url"] == (
        "https://cwe-api.mitre.org/api/v1/"
        "cwe/weakness/all"
    )


def test_unit_fetch_all_weaknesses_retries_invalid_json(
    connector_factory,
    multiple_cwes_payload: dict[str, Any],
) -> None:
    json_error = requests.JSONDecodeError(
        "Invalid JSON",
        "truncated",
        0,
    )

    connector, session = connector_factory(
        [
            FakeResponse(
                json_error=json_error
            ),
            FakeResponse(
                json_data=multiple_cwes_payload
            ),
        ]
    )

    result = connector.fetch_all_weaknesses(
        attempts=2
    )

    assert result == multiple_cwes_payload
    assert len(session.calls) == 2


def test_unit_fetch_all_weaknesses_retries_invalid_structure(
    connector_factory,
    multiple_cwes_payload: dict[str, Any],
) -> None:
    connector, session = connector_factory(
        [
            FakeResponse(
                json_data={
                    "Weaknesses": None,
                }
            ),
            FakeResponse(
                json_data=multiple_cwes_payload
            ),
        ]
    )

    result = connector.fetch_all_weaknesses(
        attempts=2
    )

    assert result == multiple_cwes_payload
    assert len(session.calls) == 2


def test_unit_fetch_all_weaknesses_fails_after_all_attempts(
    connector_factory,
) -> None:
    connector, session = connector_factory(
        [
            FakeResponse(
                json_data={
                    "Weaknesses": None,
                }
            ),
            FakeResponse(
                json_data={
                    "Weaknesses": {},
                }
            ),
        ]
    )

    with pytest.raises(
        ValueError,
        match=(
            "Unable to retrieve a complete CWE catalog "
            "after 2 attempt"
        ),
    ):
        connector.fetch_all_weaknesses(
            attempts=2
        )

    assert len(session.calls) == 2


@pytest.mark.parametrize(
    "attempts",
    [
        0,
        -1,
        True,
        False,
    ],
)
def test_unit_fetch_all_rejects_invalid_attempt_values(
    connector_factory,
    attempts: Any,
) -> None:
    connector, _ = connector_factory([])

    with pytest.raises(
        ValueError,
        match="attempts must be greater than zero",
    ):
        connector.fetch_all_weaknesses(
            attempts=attempts
        )


@pytest.mark.parametrize(
    "attempts",
    [
        None,
        1.5,
        "2",
        [],
    ],
)
def test_unit_fetch_all_rejects_invalid_attempt_types(
    connector_factory,
    attempts: Any,
) -> None:
    connector, _ = connector_factory([])

    with pytest.raises(
        TypeError,
        match="attempts must be an integer",
    ):
        connector.fetch_all_weaknesses(
            attempts=attempts
        )


# ============================================================
# Multiple weakness tests
# ============================================================


def test_unit_fetch_multiple_weaknesses(
    connector_factory,
    multiple_cwes_payload: dict[str, Any],
) -> None:
    connector, session = connector_factory(
        [
            FakeResponse(
                json_data=multiple_cwes_payload
            )
        ]
    )

    result = connector.fetch_weaknesses(
        [
            "CWE-79",
            "CWE-89",
            "CWE-502",
        ]
    )

    assert result == multiple_cwes_payload

    assert session.calls[0]["url"] == (
        "https://cwe-api.mitre.org/api/v1/"
        "cwe/weakness/79,89,502"
    )


def test_unit_fetch_multiple_weaknesses_deduplicates_ids(
    connector_factory,
    multiple_cwes_payload: dict[str, Any],
) -> None:
    connector, session = connector_factory(
        [
            FakeResponse(
                json_data=multiple_cwes_payload
            )
        ]
    )

    connector.fetch_weaknesses(
        [
            "CWE-79",
            79,
            "79",
            "00079",
            "CWE-89",
            "cwe-89",
            "CWE-502",
        ]
    )

    assert session.calls[0]["url"].endswith(
        "/cwe/weakness/79,89,502"
    )


def test_unit_fetch_multiple_weaknesses_empty_input(
    connector_factory,
) -> None:
    connector, session = connector_factory([])

    result = connector.fetch_weaknesses([])

    assert result == {
        "Weaknesses": [],
    }

    assert session.calls == []


def test_unit_fetch_multiple_weaknesses_merges_batches(
    connector_factory,
) -> None:
    first_response = {
        "Weaknesses": [
            {
                "ID": "79",
                "Name": "Cross-site Scripting",
            },
            {
                "ID": "89",
                "Name": "SQL Injection",
            },
        ]
    }

    second_response = {
        "Weaknesses": [
            {
                "ID": "502",
                "Name": (
                    "Deserialization of Untrusted Data"
                ),
            }
        ]
    }

    connector, session = connector_factory(
        [
            FakeResponse(
                json_data=first_response
            ),
            FakeResponse(
                json_data=second_response
            ),
        ]
    )

    connector.MAX_IDS_PER_REQUEST = 2

    result = connector.fetch_weaknesses(
        [
            "CWE-79",
            "CWE-89",
            "CWE-502",
        ]
    )

    assert len(session.calls) == 2

    assert session.calls[0]["url"].endswith(
        "/cwe/weakness/79,89"
    )

    assert session.calls[1]["url"].endswith(
        "/cwe/weakness/502"
    )

    assert [
        weakness["ID"]
        for weakness in result["Weaknesses"]
    ] == [
        "79",
        "89",
        "502",
    ]


def test_unit_fetch_multiple_weaknesses_deduplicates_response_entries(
    connector_factory,
) -> None:
    first_response = {
        "Weaknesses": [
            {
                "ID": "079",
                "Name": "Cross-site Scripting",
            },
            {
                "ID": "89",
                "Name": "SQL Injection",
            },
        ]
    }

    second_response = {
        "Weaknesses": [
            {
                "ID": "00089",
                "Name": "SQL Injection",
            },
            {
                "ID": "502",
                "Name": (
                    "Deserialization of Untrusted Data"
                ),
            },
        ]
    }

    connector, _ = connector_factory(
        [
            FakeResponse(
                json_data=first_response
            ),
            FakeResponse(
                json_data=second_response
            ),
        ]
    )

    connector.MAX_IDS_PER_REQUEST = 2

    result = connector.fetch_weaknesses(
        [
            "CWE-79",
            "CWE-89",
            "CWE-502",
            "CWE-1000",
        ]
    )

    assert [
        weakness["ID"]
        for weakness in result["Weaknesses"]
    ] == [
        "079",
        "89",
        "502",
    ]


def test_unit_fetch_multiple_weaknesses_preserves_missing_id_records(
    connector_factory,
) -> None:
    connector, _ = connector_factory(
        [
            FakeResponse(
                json_data={
                    "Weaknesses": [
                        {
                            "Name": "First missing ID",
                        },
                        {
                            "Name": "Second missing ID",
                        },
                    ]
                }
            )
        ]
    )

    result = connector.fetch_weaknesses(
        ["CWE-79"]
    )

    assert len(result["Weaknesses"]) == 2


def test_unit_fetch_multiple_rejects_non_dict_response_items(
    connector_factory,
) -> None:
    connector, _ = connector_factory(
        [
            FakeResponse(
                json_data={
                    "Weaknesses": [
                        {
                            "ID": "79",
                        },
                        None,
                    ]
                }
            )
        ]
    )

    with pytest.raises(
        ValueError,
        match=(
            "every Weaknesses element must "
            "be a JSON object"
        ),
    ):
        connector.fetch_weaknesses(
            ["CWE-79"]
        )


# ============================================================
# CWE metadata tests
# ============================================================


def test_unit_fetch_cwe_metadata(
    connector_factory,
) -> None:
    payload = [
        {
            "Type": "weakness",
            "ID": "79",
        },
        {
            "Type": "view",
            "ID": "1000",
        },
    ]

    connector, session = connector_factory(
        [
            FakeResponse(
                json_data=payload
            )
        ]
    )

    result = connector.fetch_cwe_metadata(
        [
            "CWE-79",
            "CWE-1000",
        ]
    )

    assert result == payload

    assert session.calls[0]["url"].endswith(
        "/cwe/79,1000"
    )


def test_unit_fetch_cwe_metadata_accepts_empty_response_list(
    connector_factory,
) -> None:
    connector, _ = connector_factory(
        [
            FakeResponse(
                json_data=[]
            )
        ]
    )

    assert connector.fetch_cwe_metadata(
        ["CWE-79"]
    ) == []


def test_unit_fetch_cwe_metadata_rejects_empty_ids(
    connector_factory,
) -> None:
    connector, session = connector_factory([])

    with pytest.raises(
        ValueError,
        match=(
            "At least one CWE identifier "
            "is required"
        ),
    ):
        connector.fetch_cwe_metadata([])

    assert session.calls == []


@pytest.mark.parametrize(
    "invalid_payload",
    [
        None,
        {},
        "invalid",
        123,
    ],
)
def test_unit_fetch_cwe_metadata_rejects_invalid_payload(
    connector_factory,
    invalid_payload: Any,
) -> None:
    connector, _ = connector_factory(
        [
            FakeResponse(
                json_data=invalid_payload
            )
        ]
    )

    with pytest.raises(
        ValueError,
        match="Invalid CWE metadata response",
    ):
        connector.fetch_cwe_metadata(
            ["CWE-79"]
        )


def test_unit_fetch_cwe_metadata_rejects_invalid_list_element(
    connector_factory,
) -> None:
    connector, _ = connector_factory(
        [
            FakeResponse(
                json_data=[
                    {
                        "Type": "weakness",
                        "ID": "79",
                    },
                    None,
                ]
            )
        ]
    )

    with pytest.raises(
        ValueError,
        match=(
            "every element must be a JSON object"
        ),
    ):
        connector.fetch_cwe_metadata(
            ["CWE-79"]
        )


# ============================================================
# Relationship tests
# ============================================================


@pytest.mark.parametrize(
    (
        "method_name",
        "relationship",
    ),
    [
        (
            "fetch_parents",
            "parents",
        ),
        (
            "fetch_children",
            "children",
        ),
        (
            "fetch_descendants",
            "descendants",
        ),
    ],
)
def test_unit_fetch_relationships(
    connector_factory,
    method_name: str,
    relationship: str,
) -> None:
    payload = [
        {
            "Type": "class_weakness",
            "ID": "74",
            "ViewID": "1000",
            "Primary_Parent": True,
        }
    ]

    connector, session = connector_factory(
        [
            FakeResponse(
                json_data=payload
            )
        ]
    )

    method = getattr(
        connector,
        method_name,
    )

    result = method(
        "CWE-79",
        view="1000",
    )

    assert result == payload

    call = session.calls[0]

    assert call["url"].endswith(
        f"/cwe/79/{relationship}"
    )

    assert call["params"] == {
        "view": "1000",
    }


def test_unit_fetch_relationships_without_view(
    connector_factory,
) -> None:
    connector, session = connector_factory(
        [
            FakeResponse(
                json_data=[]
            )
        ]
    )

    result = connector.fetch_parents(
        "CWE-79"
    )

    assert result == []
    assert session.calls[0]["params"] == {}


def test_unit_fetch_ancestors_with_primary_parameter(
    connector_factory,
) -> None:
    payload = [
        {
            "Type": "class_weakness",
            "ID": "74",
            "ViewID": "1000",
        }
    ]

    connector, session = connector_factory(
        [
            FakeResponse(
                json_data=payload
            )
        ]
    )

    result = connector.fetch_ancestors(
        "CWE-79",
        view=1000,
        primary=True,
    )

    assert result == payload

    call = session.calls[0]

    assert call["url"].endswith(
        "/cwe/79/ancestors"
    )

    assert call["params"] == {
        "view": "1000",
        "primary": True,
    }


@pytest.mark.parametrize(
    "invalid_payload",
    [
        None,
        {},
        "invalid",
        123,
    ],
)
def test_unit_relationship_rejects_non_list_response(
    connector_factory,
    invalid_payload: Any,
) -> None:
    connector, _ = connector_factory(
        [
            FakeResponse(
                json_data=invalid_payload
            )
        ]
    )

    with pytest.raises(
        ValueError,
        match="expected a JSON list",
    ):
        connector.fetch_parents(
            "CWE-79"
        )


def test_unit_relationship_rejects_invalid_list_element(
    connector_factory,
) -> None:
    connector, _ = connector_factory(
        [
            FakeResponse(
                json_data=[
                    {
                        "ID": "74",
                    },
                    None,
                ]
            )
        ]
    )

    with pytest.raises(
        ValueError,
        match=(
            "every element must be "
            "a JSON object"
        ),
    ):
        connector.fetch_parents(
            "CWE-79"
        )


def test_unit_fetch_relationships_rejects_unsupported_relationship(
    connector_factory,
) -> None:
    connector, session = connector_factory([])

    with pytest.raises(
        ValueError,
        match="Unsupported CWE relationship",
    ):
        connector._fetch_relationships(
            cwe_id="CWE-79",
            relationship="siblings",
            view=None,
        )

    assert session.calls == []


# ============================================================
# HTTP tests
# ============================================================


def test_unit_404_is_converted_to_lookup_error(
    connector_factory,
) -> None:
    connector, _ = connector_factory(
        [
            FakeResponse(
                status_code=404
            )
        ]
    )

    with pytest.raises(
        LookupError,
        match="CWE API resource not found",
    ):
        connector.fetch_weakness(
            "CWE-999999"
        )


@pytest.mark.parametrize(
    "status_code",
    [
        400,
        401,
        403,
        429,
        500,
        502,
        503,
    ],
)
def test_unit_http_errors_become_connection_error(
    connector_factory,
    status_code: int,
) -> None:
    connector, _ = connector_factory(
        [
            FakeResponse(
                status_code=status_code
            )
        ]
    )

    with pytest.raises(
        ConnectionError,
        match=(
            "CWE API request failed with "
            f"HTTP status {status_code}"
        ),
    ):
        connector.fetch_version()


def test_unit_network_error_is_propagated() -> None:
    class FailingSession(FakeSession):
        def get(
            self,
            url: str,
            *,
            params: dict[str, Any] | None = None,
            timeout: int | float | None = None,
        ) -> FakeResponse:
            raise requests.Timeout(
                "Simulated timeout."
            )

    connector = CWEConnector(
        session=FailingSession(),  # type: ignore[arg-type]
    )

    with pytest.raises(
        requests.Timeout,
        match="Simulated timeout",
    ):
        connector.fetch_version()


def test_unit_invalid_json_is_rejected(
    connector_factory,
) -> None:
    json_error = requests.JSONDecodeError(
        "Invalid JSON",
        "not-json",
        0,
    )

    connector, _ = connector_factory(
        [
            FakeResponse(
                json_error=json_error
            )
        ]
    )

    with pytest.raises(
        ValueError,
        match=(
            "CWE API returned an invalid "
            "JSON response"
        ),
    ):
        connector.fetch_version()


@pytest.mark.parametrize(
    "endpoint",
    [
        "",
        " ",
    ],
)
def test_unit_get_json_rejects_empty_endpoint(
    connector_factory,
    endpoint: str,
) -> None:
    connector, session = connector_factory([])

    with pytest.raises(
        ValueError,
        match="endpoint cannot be empty",
    ):
        connector._get_json(endpoint)

    assert session.calls == []


@pytest.mark.parametrize(
    "endpoint",
    [
        None,
        123,
        [],
    ],
)
def test_unit_get_json_rejects_invalid_endpoint_type(
    connector_factory,
    endpoint: Any,
) -> None:
    connector, session = connector_factory([])

    with pytest.raises(
        TypeError,
        match="endpoint must be a string",
    ):
        connector._get_json(endpoint)

    assert session.calls == []


def test_unit_get_json_adds_missing_leading_slash(
    connector_factory,
    version_payload: dict[str, Any],
) -> None:
    connector, session = connector_factory(
        [
            FakeResponse(
                json_data=version_payload
            )
        ]
    )

    result = connector._get_json(
        "cwe/version"
    )

    assert result == version_payload

    assert session.calls[0]["url"] == (
        "https://cwe-api.mitre.org/api/v1/"
        "cwe/version"
    )


# ============================================================
# Weakness response validation
# ============================================================


@pytest.mark.parametrize(
    "invalid_payload",
    [
        None,
        [],
        "invalid",
        123,
        {},
        {
            "Weaknesses": None,
        },
        {
            "Weaknesses": {},
        },
    ],
)
def test_unit_weakness_response_validation(
    invalid_payload: Any,
) -> None:
    """
    Validate malformed weakness payloads directly.

    fetch_all_weaknesses() intentionally wraps validation failures
    in a catalog-retrieval error after exhausting its attempts.
    """

    with pytest.raises(
        ValueError,
        match="Invalid CWE weakness response",
    ):
        CWEConnector._validate_weakness_response(
            invalid_payload
        )
        
def test_unit_weakness_response_rejects_invalid_elements(
) -> None:
    payload = {
        "Weaknesses": [
            {
                "ID": "79",
            },
            None,
        ]
    }

    with pytest.raises(
        ValueError,
        match=(
            "every Weaknesses element must "
            "be a JSON object"
        ),
    ):
        CWEConnector._validate_weakness_response(
            payload
        )


# ============================================================
# CWE identifier normalization
# ============================================================


@pytest.mark.parametrize(
    (
        "raw_identifier",
        "expected",
    ),
    [
        (
            "CWE-79",
            "79",
        ),
        (
            "cwe-79",
            "79",
        ),
        (
            "79",
            "79",
        ),
        (
            79,
            "79",
        ),
        (
            " CWE-79 ",
            "79",
        ),
        (
            "00079",
            "79",
        ),
        (
            "CWE-00079",
            "79",
        ),
        (
            502,
            "502",
        ),
    ],
)
def test_unit_normalize_cwe_id(
    raw_identifier: str | int,
    expected: str,
) -> None:
    assert (
        CWEConnector._normalize_cwe_id(
            raw_identifier
        )
        == expected
    )


@pytest.mark.parametrize(
    "invalid_identifier",
    [
        "",
        " ",
        "CWE-",
        "CWE-ABC",
        "ABC-79",
        "CWE-79-extra",
        "CWE--79",
        "0",
        "CWE-0",
        "00000",
        "CWE-00000",
        0,
        -1,
        True,
        False,
    ],
)
def test_unit_normalize_cwe_id_rejects_invalid_values(
    invalid_identifier: Any,
) -> None:
    with pytest.raises(ValueError):
        CWEConnector._normalize_cwe_id(
            invalid_identifier
        )


@pytest.mark.parametrize(
    "invalid_identifier",
    [
        None,
        7.9,
        [],
        {},
    ],
)
def test_unit_normalize_cwe_id_rejects_invalid_types(
    invalid_identifier: Any,
) -> None:
    with pytest.raises(TypeError):
        CWEConnector._normalize_cwe_id(
            invalid_identifier
        )


def test_unit_normalize_cwe_ids_preserves_order_and_deduplicates(
) -> None:
    result = CWEConnector._normalize_cwe_ids(
        [
            "CWE-502",
            "CWE-79",
            502,
            "79",
            "00079",
            "CWE-89",
        ]
    )

    assert result == [
        "502",
        "79",
        "89",
    ]


@pytest.mark.parametrize(
    "invalid_values",
    [
        "CWE-79",
        b"CWE-79",
    ],
)
def test_unit_normalize_cwe_ids_rejects_single_string(
    invalid_values: Any,
) -> None:
    with pytest.raises(
        TypeError,
        match=(
            "must be an iterable of identifiers"
        ),
    ):
        CWEConnector._normalize_cwe_ids(
            invalid_values
        )


@pytest.mark.parametrize(
    "invalid_values",
    [
        None,
        123,
        7.9,
    ],
)
def test_unit_normalize_cwe_ids_rejects_non_iterable(
    invalid_values: Any,
) -> None:
    with pytest.raises(
        TypeError,
        match=(
            "must be an iterable of identifiers"
        ),
    ):
        CWEConnector._normalize_cwe_ids(
            invalid_values
        )


@pytest.mark.parametrize(
    (
        "raw_identifier",
        "expected",
    ),
    [
        (
            "79",
            "79",
        ),
        (
            "00079",
            "79",
        ),
        (
            502,
            "502",
        ),
        (
            None,
            None,
        ),
        (
            "invalid",
            None,
        ),
        (
            True,
            None,
        ),
    ],
)
def test_unit_normalize_response_cwe_id(
    raw_identifier: Any,
    expected: str | None,
) -> None:
    assert (
        CWEConnector._normalize_response_cwe_id(
            raw_identifier
        )
        == expected
    )


# ============================================================
# Chunking tests
# ============================================================


def test_unit_chunked_splits_values() -> None:
    result = list(
        CWEConnector._chunked(
            [
                "1",
                "2",
                "3",
                "4",
                "5",
            ],
            size=2,
        )
    )

    assert result == [
        [
            "1",
            "2",
        ],
        [
            "3",
            "4",
        ],
        [
            "5",
        ],
    ]


@pytest.mark.parametrize(
    "size",
    [
        0,
        -1,
        True,
        False,
    ],
)
def test_unit_chunked_rejects_invalid_size_values(
    size: Any,
) -> None:
    with pytest.raises(
        ValueError,
        match=(
            "Chunk size must be greater than zero"
        ),
    ):
        list(
            CWEConnector._chunked(
                ["1"],
                size=size,
            )
        )


@pytest.mark.parametrize(
    "size",
    [
        None,
        1.5,
        "2",
    ],
)
def test_unit_chunked_rejects_invalid_size_types(
    size: Any,
) -> None:
    with pytest.raises(
        TypeError,
        match="Chunk size must be an integer",
    ):
        list(
            CWEConnector._chunked(
                ["1"],
                size=size,
            )
        )


# ============================================================
# Integration tests: real MITRE CWE REST API
# ============================================================


@pytest.mark.integration
def test_integration_fetch_current_cwe_version(
) -> None:
    """
    Retrieve live CWE catalog metadata.
    """

    connector = CWEConnector()

    result = connector.fetch_version()

    print(
        "\n========== CWE CATALOG VERSION =========="
    )

    for key, value in result.items():
        print(f"{key:<25}: {value}")

    assert isinstance(result, dict)
    assert result

    assert isinstance(
        result.get("ContentVersion"),
        str,
    )

    assert isinstance(
        result.get("TotalWeaknesses"),
        int,
    )

    assert result["TotalWeaknesses"] > 500


@pytest.mark.integration
def test_integration_fetch_cwe_79(
) -> None:
    """
    Retrieve the stable CWE-79 entry.
    """

    connector = CWEConnector()

    result = connector.fetch_weakness(
        "CWE-79"
    )

    weaknesses = result["Weaknesses"]

    assert isinstance(weaknesses, list)
    assert len(weaknesses) >= 1

    weakness = weaknesses[0]

    print(
        "\n========== CWE-79 =========="
    )
    print(
        f"ID          : {weakness.get('ID')}"
    )
    print(
        f"Name        : {weakness.get('Name')}"
    )
    print(
        f"Abstraction : "
        f"{weakness.get('Abstraction')}"
    )
    print(
        f"Status      : {weakness.get('Status')}"
    )

    assert isinstance(weakness, dict)

    assert str(
        weakness.get("ID")
    ) == "79"

    assert isinstance(
        weakness.get("Name"),
        str,
    )

    assert weakness.get("Name")


@pytest.mark.integration
def test_integration_fetch_multiple_cwes(
) -> None:
    """
    Retrieve several known CWE entries.
    """

    connector = CWEConnector()

    requested_ids = {
        "22",
        "79",
        "89",
        "502",
    }

    result = connector.fetch_weaknesses(
        [
            "CWE-22",
            "CWE-79",
            "CWE-89",
            "CWE-502",
        ]
    )

    weaknesses = result["Weaknesses"]

    returned_ids = {
        str(weakness.get("ID"))
        for weakness in weaknesses
        if isinstance(weakness, dict)
    }

    print(
        "\n========== MULTIPLE CWE ENTRIES =========="
    )

    for weakness in weaknesses:
        print(
            f"CWE-{weakness.get('ID')}: "
            f"{weakness.get('Name')}"
        )

    assert requested_ids.issubset(
        returned_ids
    )


@pytest.mark.integration
@pytest.mark.external_unstable
def test_integration_fetch_all_weaknesses(
) -> None:
    """
    Attempt to retrieve the complete CWE catalog.

    The remote endpoint may return a truncated JSON body despite
    HTTP 200. Such an upstream failure is recorded as xfail rather
    than failing the whole connector integration suite.
    """

    connector = CWEConnector(
        timeout=90
    )

    try:
        result = connector.fetch_all_weaknesses(
            attempts=2
        )

    except ValueError as error:
        pytest.xfail(
            "The external CWE /weakness/all endpoint "
            f"returned an incomplete or invalid response: {error}"
        )

    weaknesses = result["Weaknesses"]

    print(
        "\n========== COMPLETE CWE CATALOG =========="
    )
    print(
        f"Weaknesses received: {len(weaknesses)}"
    )

    assert isinstance(weaknesses, list)
    assert len(weaknesses) > 500

    ids = {
        str(weakness.get("ID"))
        for weakness in weaknesses
        if isinstance(weakness, dict)
    }

    assert "22" in ids
    assert "79" in ids
    assert "89" in ids
    assert "502" in ids


@pytest.mark.integration
def test_integration_fetch_cwe_metadata(
) -> None:
    """
    Verify the generic CWE metadata endpoint.
    """

    connector = CWEConnector()

    result = connector.fetch_cwe_metadata(
        [
            "CWE-79",
        ]
    )

    print(
        "\n========== CWE-79 METADATA =========="
    )

    for item in result:
        print(item)

    assert isinstance(result, list)
    assert len(result) >= 1

    for item in result:
        assert isinstance(item, dict)

    assert any(
        str(item.get("ID")) == "79"
        for item in result
    )


@pytest.mark.integration
def test_integration_fetch_cwe_79_relationships(
) -> None:
    """
    Verify that the live hierarchy endpoint returns a valid list.
    """

    connector = CWEConnector()

    parents = connector.fetch_parents(
        "CWE-79",
        view="1000",
    )

    print(
        "\n========== CWE-79 PARENTS =========="
    )

    for parent in parents:
        print(parent)

    assert isinstance(parents, list)

    for parent in parents:
        assert isinstance(parent, dict)