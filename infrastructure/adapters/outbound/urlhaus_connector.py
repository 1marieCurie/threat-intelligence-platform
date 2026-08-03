from __future__ import annotations

from dotenv import find_dotenv, load_dotenv

load_dotenv(
    dotenv_path=find_dotenv(usecwd=True),
    override=False,
)


import os
import re
from typing import Any
from urllib.parse import urlsplit

import requests
from requests import Response, Session


class URLhausConnectorError(RuntimeError):
    """
    Base exception raised by the URLhaus connector.
    """


class URLhausAuthenticationError(
    URLhausConnectorError
):
    """
    Raised when the URLhaus Auth-Key is missing or rejected.
    """


class URLhausHTTPError(
    URLhausConnectorError
):
    """
    Raised when URLhaus returns an unexpected HTTP response.
    """


class URLhausResponseError(
    URLhausConnectorError
):
    """
    Raised when URLhaus returns an invalid response structure.
    """


class URLhausQueryError(
    URLhausConnectorError
):
    """
    Raised when URLhaus returns an unsuccessful query status.
    """


class URLhausConnector:
    """
    HTTP adapter for the URLhaus API.

    Responsibilities:

    - authenticate requests;
    - call URLhaus endpoints;
    - validate transport-level responses;
    - validate the JSON envelope;
    - return raw dictionaries.

    This connector performs no business normalization and no
    persistence.
    """

    BASE_URL = (
        "https://urlhaus-api.abuse.ch/v1"
    )

    RECENT_URLS_ENDPOINT = (
        "/urls/recent/"
    )

    URL_INFORMATION_ENDPOINT = (
        "/url/"
    )

    URL_ID_INFORMATION_ENDPOINT = (
        "/urlid/"
    )

    HOST_INFORMATION_ENDPOINT = (
        "/host/"
    )

    RECENT_PAYLOADS_ENDPOINT = (
        "/payloads/recent/"
    )

    PAYLOAD_INFORMATION_ENDPOINT = (
        "/payload/"
    )

    DEFAULT_TIMEOUT = 30.0
    MAX_RECENT_LIMIT = 1_000

    SUCCESS_QUERY_STATUS = "ok"
    EMPTY_QUERY_STATUS = "no_results"

    _SAFE_QUERY_STATUS_PATTERN = re.compile(
        r"\A[a-z0-9_]{1,64}\Z"
    )

    def __init__(
        self,
        auth_key: str | None = None,
        *,
        session: Session | None = None,
        timeout: float = DEFAULT_TIMEOUT,
        base_url: str = BASE_URL,
        user_agent: str = (
            "threat-intelligence-engine/0.1"
        ),
    ) -> None:
        resolved_auth_key = (
            self._resolve_auth_key(
                auth_key
            )
        )

        self._timeout = (
            self._validate_timeout(
                timeout
            )
        )

        self._base_url = (
            self._normalize_base_url(
                base_url
            )
        )

        normalized_user_agent = (
            self._validate_non_empty_string(
                value=user_agent,
                field_name="user_agent",
            )
        )

        self._session = (
            session
            if session is not None
            else requests.Session()
        )

        # The key remains confined to the private HTTP headers.
        # Never log this dictionary or connector.__dict__.
        self._headers = {
            "Auth-Key": resolved_auth_key,
            "Accept": "application/json",
            "User-Agent": (
                normalized_user_agent
            ),
        }

    @property
    def canonical_source_url(
        self,
    ) -> str:
        """
        Return the non-authenticated canonical provider URL.
        """

        return self._base_url

    # ========================================================
    # Public collection methods
    # ========================================================

    def fetch_recent_urls(
        self,
        limit: int | None = None,
    ) -> dict[str, Any]:
        endpoint = (
            self.RECENT_URLS_ENDPOINT
        )

        if limit is not None:
            normalized_limit = (
                self._validate_limit(
                    limit
                )
            )

            endpoint = (
                f"{self.RECENT_URLS_ENDPOINT}"
                f"limit/{normalized_limit}/"
            )

        return self._get(
            endpoint
        )

    def fetch_url_information(
        self,
        url: str,
    ) -> dict[str, Any]:
        normalized_url = (
            self._validate_non_empty_string(
                value=url,
                field_name="url",
            )
        )

        return self._post(
            self.URL_INFORMATION_ENDPOINT,
            data={
                "url": normalized_url,
            },
        )

    def fetch_url_information_by_id(
        self,
        urlhaus_id: str | int,
    ) -> dict[str, Any]:
        normalized_id = (
            self._validate_urlhaus_id(
                urlhaus_id
            )
        )

        return self._post(
            self.URL_ID_INFORMATION_ENDPOINT,
            data={
                "urlid": normalized_id,
            },
        )

    def fetch_host_information(
        self,
        host: str,
    ) -> dict[str, Any]:
        normalized_host = (
            self._validate_non_empty_string(
                value=host,
                field_name="host",
            )
        )

        return self._post(
            self.HOST_INFORMATION_ENDPOINT,
            data={
                "host": normalized_host,
            },
        )

    def fetch_recent_payloads(
        self,
        limit: int | None = None,
    ) -> dict[str, Any]:
        endpoint = (
            self.RECENT_PAYLOADS_ENDPOINT
        )

        if limit is not None:
            normalized_limit = (
                self._validate_limit(
                    limit
                )
            )

            endpoint = (
                f"{self.RECENT_PAYLOADS_ENDPOINT}"
                f"limit/{normalized_limit}/"
            )

        return self._get(
            endpoint
        )

    def fetch_payload_information(
        self,
        *,
        md5_hash: str | None = None,
        sha256_hash: str | None = None,
    ) -> dict[str, Any]:
        supplied_hashes = [
            value
            for value in (
                md5_hash,
                sha256_hash,
            )
            if value is not None
        ]

        if len(supplied_hashes) != 1:
            raise ValueError(
                "Provide exactly one of "
                "md5_hash or sha256_hash."
            )

        if md5_hash is not None:
            normalized_hash = (
                self._validate_hash(
                    value=md5_hash,
                    expected_length=32,
                    field_name="md5_hash",
                )
            )

            payload = {
                "md5_hash": normalized_hash,
            }

        else:
            normalized_hash = (
                self._validate_hash(
                    value=sha256_hash,
                    expected_length=64,
                    field_name="sha256_hash",
                )
            )

            payload = {
                "sha256_hash": (
                    normalized_hash
                ),
            }

        return self._post(
            self.PAYLOAD_INFORMATION_ENDPOINT,
            data=payload,
        )

    # ========================================================
    # HTTP helpers
    # ========================================================

    def _get(
        self,
        endpoint: str,
    ) -> dict[str, Any]:
        request_url = self._build_url(
            endpoint
        )

        try:
            response = self._session.get(
                request_url,
                headers=dict(
                    self._headers
                ),
                timeout=self._timeout,
            )

        except requests.Timeout as error:
            raise URLhausHTTPError(
                "URLhaus GET request timed out."
            ) from error

        except requests.RequestException as error:
            # Do not propagate the original exception message:
            # requests may include URLs, parameters or headers.
            raise URLhausHTTPError(
                "URLhaus GET request failed."
            ) from error

        return self._process_response(
            response
        )

    def _post(
        self,
        endpoint: str,
        *,
        data: dict[str, str],
    ) -> dict[str, Any]:
        request_url = self._build_url(
            endpoint
        )

        try:
            response = self._session.post(
                request_url,
                headers=dict(
                    self._headers
                ),
                data=dict(
                    data
                ),
                timeout=self._timeout,
            )

        except requests.Timeout as error:
            raise URLhausHTTPError(
                "URLhaus POST request timed out."
            ) from error

        except requests.RequestException as error:
            # POST data may contain a malicious URL or hash.
            raise URLhausHTTPError(
                "URLhaus POST request failed."
            ) from error

        return self._process_response(
            response
        )

    def _process_response(
        self,
        response: Response,
    ) -> dict[str, Any]:
        status_code = (
            response.status_code
        )

        if status_code in {
            401,
            403,
        }:
            raise URLhausAuthenticationError(
                "URLhaus rejected the Auth-Key."
            )

        try:
            response.raise_for_status()

        except requests.HTTPError as error:
            # The response body is deliberately excluded. It may
            # contain an IOC, reflected input or provider details.
            raise URLhausHTTPError(
                "URLhaus returned HTTP "
                f"{status_code}."
            ) from error

        try:
            payload = response.json()

        except ValueError as error:
            # Never include response.text in this exception.
            raise URLhausResponseError(
                "URLhaus returned invalid JSON."
            ) from error

        if not isinstance(
            payload,
            dict,
        ):
            raise URLhausResponseError(
                "URLhaus response root must "
                "be a JSON object."
            )

        query_status = payload.get(
            "query_status"
        )

        if not isinstance(
            query_status,
            str,
        ):
            raise URLhausResponseError(
                "URLhaus response does not "
                "contain a valid "
                "'query_status' field."
            )

        if query_status in {
            self.SUCCESS_QUERY_STATUS,
            self.EMPTY_QUERY_STATUS,
        }:
            return payload

        raise URLhausQueryError(
            self._build_query_error_message(
                query_status
            )
        )

    # ========================================================
    # Validation helpers
    # ========================================================

    @staticmethod
    def _resolve_auth_key(
        auth_key: str | None,
    ) -> str:
        resolved_auth_key = (
            auth_key
            if auth_key is not None
            else os.getenv(
                "URLHAUS_AUTH_KEY"
            )
        )

        if not isinstance(
            resolved_auth_key,
            str,
        ):
            raise URLhausAuthenticationError(
                "URLhaus Auth-Key is required. "
                "Pass auth_key or set the "
                "URLHAUS_AUTH_KEY environment "
                "variable."
            )

        normalized_auth_key = (
            resolved_auth_key.strip()
        )

        if not normalized_auth_key:
            raise URLhausAuthenticationError(
                "URLhaus Auth-Key must not "
                "be empty."
            )

        return normalized_auth_key

    @staticmethod
    def _validate_timeout(
        timeout: float,
    ) -> float:
        if (
            isinstance(timeout, bool)
            or not isinstance(
                timeout,
                (int, float),
            )
            or timeout <= 0
        ):
            raise ValueError(
                "URLhaus timeout must be "
                "a positive number."
            )

        return float(
            timeout
        )

    @staticmethod
    def _normalize_base_url(
        base_url: str,
    ) -> str:
        if not isinstance(
            base_url,
            str,
        ):
            raise TypeError(
                "URLhaus base_url must "
                "be a string."
            )

        normalized_base_url = (
            base_url.strip().rstrip("/")
        )

        if not normalized_base_url:
            raise ValueError(
                "URLhaus base_url must "
                "not be empty."
            )

        parsed_url = urlsplit(
            normalized_base_url
        )

        if (
            parsed_url.scheme
            not in {
                "http",
                "https",
            }
            or not parsed_url.hostname
        ):
            raise ValueError(
                "URLhaus base_url must be "
                "a valid HTTP URL."
            )

        if (
            parsed_url.username is not None
            or parsed_url.password is not None
            or parsed_url.query
            or parsed_url.fragment
        ):
            raise ValueError(
                "URLhaus base_url must not "
                "contain credentials, query "
                "parameters or fragments."
            )

        return normalized_base_url

    def _build_url(
        self,
        endpoint: str,
    ) -> str:
        normalized_endpoint = (
            self._validate_non_empty_string(
                value=endpoint,
                field_name="endpoint",
            )
        )

        if not normalized_endpoint.startswith(
            "/"
        ):
            normalized_endpoint = (
                f"/{normalized_endpoint}"
            )

        return (
            f"{self._base_url}"
            f"{normalized_endpoint}"
        )

    def _validate_limit(
        self,
        limit: int,
    ) -> int:
        # ValueError is preserved for compatibility with the
        # existing public connector tests.
        if (
            isinstance(limit, bool)
            or not isinstance(
                limit,
                int,
            )
        ):
            raise ValueError(
                "URLhaus limit must be "
                "an integer."
            )

        if not (
            1
            <= limit
            <= self.MAX_RECENT_LIMIT
        ):
            raise ValueError(
                "URLhaus limit must be "
                "between 1 and "
                f"{self.MAX_RECENT_LIMIT}."
            )

        return limit

    @staticmethod
    def _validate_urlhaus_id(
        value: str | int,
    ) -> str:
        if isinstance(
            value,
            bool,
        ):
            raise ValueError(
                "URLhaus ID must be "
                "a positive integer."
            )

        if isinstance(
            value,
            int,
        ):
            parsed_value = value

        elif isinstance(
            value,
            str,
        ):
            normalized_value = (
                value.strip()
            )

            if (
                not normalized_value
                or not normalized_value.isascii()
                or not normalized_value.isdigit()
            ):
                raise ValueError(
                    "URLhaus ID must be "
                    "a positive integer."
                )

            parsed_value = int(
                normalized_value
            )

        else:
            raise ValueError(
                "URLhaus ID must be "
                "a positive integer."
            )

        if parsed_value <= 0:
            raise ValueError(
                "URLhaus ID must be "
                "a positive integer."
            )

        return str(
            parsed_value
        )

    @staticmethod
    def _validate_non_empty_string(
        *,
        value: str,
        field_name: str,
    ) -> str:
        if not isinstance(
            value,
            str,
        ):
            raise TypeError(
                f"{field_name} must be "
                "a string."
            )

        normalized_value = (
            value.strip()
        )

        if not normalized_value:
            raise ValueError(
                f"{field_name} must not "
                "be empty."
            )

        return normalized_value

    @staticmethod
    def _validate_hash(
        *,
        value: str | None,
        expected_length: int,
        field_name: str,
    ) -> str:
        if not isinstance(
            value,
            str,
        ):
            raise TypeError(
                f"{field_name} must be "
                "a string."
            )

        normalized_value = (
            value.strip().lower()
        )

        if (
            len(normalized_value)
            != expected_length
        ):
            raise ValueError(
                f"{field_name} must contain "
                f"exactly {expected_length} "
                "hexadecimal characters."
            )

        try:
            int(
                normalized_value,
                16,
            )

        except ValueError as error:
            raise ValueError(
                f"{field_name} must be "
                "hexadecimal."
            ) from error

        return normalized_value

    @classmethod
    def _build_query_error_message(
        cls,
        query_status: str,
    ) -> str:
        """
        Preserve useful diagnostics only for a small safe syntax.

        A malformed or reflected status is not included because it
        could contain URLs, tokens or arbitrary provider content.
        """

        if cls._SAFE_QUERY_STATUS_PATTERN.fullmatch(
            query_status
        ):
            return (
                "URLhaus query failed with "
                "query_status="
                f"{query_status!r}."
            )

        return (
            "URLhaus query failed with "
            "an unsafe query status."
        )