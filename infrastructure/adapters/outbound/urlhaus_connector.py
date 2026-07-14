from __future__ import annotations

import os
from typing import Any, Dict, Optional

import requests
from requests import Response, Session


class URLhausConnectorError(RuntimeError):
    """
    Base exception raised by the URLhaus connector.
    """


class URLhausAuthenticationError(URLhausConnectorError):
    """
    Raised when the URLhaus Auth-Key is missing or rejected.
    """


class URLhausHTTPError(URLhausConnectorError):
    """
    Raised when URLhaus returns an unexpected HTTP response.
    """


class URLhausResponseError(URLhausConnectorError):
    """
    Raised when URLhaus returns invalid JSON or an unexpected payload.
    """


class URLhausQueryError(URLhausConnectorError):
    """
    Raised when URLhaus returns an unsuccessful query_status.
    """


class URLhausConnector:
    """
    Outbound connector for the URLhaus API.

    Responsibilities:
    - authenticate HTTP requests;
    - call URLhaus endpoints;
    - validate HTTP responses;
    - validate JSON response structure;
    - return raw dictionaries to the application layer.

    This connector does not normalize URLhaus records into domain
    Threat objects. That responsibility belongs to
    URLhausThreatSource.
    """

    BASE_URL = "https://urlhaus-api.abuse.ch/v1"

    RECENT_URLS_ENDPOINT = "/urls/recent/"
    URL_INFORMATION_ENDPOINT = "/url/"
    URL_ID_INFORMATION_ENDPOINT = "/urlid/"
    HOST_INFORMATION_ENDPOINT = "/host/"
    RECENT_PAYLOADS_ENDPOINT = "/payloads/recent/"
    PAYLOAD_INFORMATION_ENDPOINT = "/payload/"

    DEFAULT_TIMEOUT = 30.0
    MAX_RECENT_LIMIT = 1000

    SUCCESS_QUERY_STATUS = "ok"
    EMPTY_QUERY_STATUS = "no_results"

    def __init__(
        self,
        auth_key: Optional[str] = None,
        *,
        session: Optional[Session] = None,
        timeout: float = DEFAULT_TIMEOUT,
        base_url: str = BASE_URL,
        user_agent: str = "threat-intelligence-engine/0.1",
    ) -> None:
        """
        Initialize the URLhaus connector.

        Args:
            auth_key:
                URLhaus Auth-Key. If omitted, the connector reads
                URLHAUS_AUTH_KEY from the environment.

            session:
                Optional requests.Session dependency. Supplying one
                makes the connector easy to test with fake sessions.

            timeout:
                Request timeout in seconds.

            base_url:
                URLhaus API base URL.

            user_agent:
                User-Agent sent with requests.

        Raises:
            ValueError:
                If timeout is invalid or base_url is empty.

            URLhausAuthenticationError:
                If no Auth-Key is available.
        """
        resolved_auth_key = (
            auth_key
            if auth_key is not None
            else os.getenv("URLHAUS_AUTH_KEY")
        )

        if not isinstance(resolved_auth_key, str):
            raise URLhausAuthenticationError(
                "URLhaus Auth-Key is required. Pass auth_key or set "
                "the URLHAUS_AUTH_KEY environment variable."
            )

        resolved_auth_key = (
        auth_key
        if auth_key is not None
        else os.getenv("URLHAUS_AUTH_KEY")
        )

        if not isinstance(resolved_auth_key, str):
            raise URLhausAuthenticationError(
                "URLhaus Auth-Key is required. Pass auth_key or set "
                "the URLHAUS_AUTH_KEY environment variable."
            )

        resolved_auth_key = resolved_auth_key.strip()

        if not resolved_auth_key:
            raise URLhausAuthenticationError(
                "URLhaus Auth-Key must not be empty."
            )

        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or timeout <= 0
        ):
            raise ValueError(
                "URLhaus timeout must be a positive number."
            )

        if not isinstance(base_url, str) or not base_url.strip():
            raise ValueError(
                "URLhaus base_url must not be empty."
            )

        if not isinstance(user_agent, str) or not user_agent.strip():
            raise ValueError(
                "URLhaus user_agent must not be empty."
            )

        self._auth_key = resolved_auth_key
        self._timeout = float(timeout)
        self._base_url = base_url.rstrip("/")
        self._session = session or requests.Session()

        self._headers = {
            "Auth-Key": self._auth_key,
            "Accept": "application/json",
            "User-Agent": user_agent.strip(),
        }

    # ============================================================
    # Public collection methods
    # ============================================================

    def fetch_recent_urls(
        self,
        limit: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Retrieve recent malware URLs added to URLhaus.

        URLhaus returns entries added during the recent collection
        window, with at most 1000 records.

        Args:
            limit:
                Optional number of records requested.
                Must be between 1 and 1000.

        Returns:
            Raw URLhaus JSON response.

        Raises:
            ValueError:
                If limit is invalid.

            URLhausConnectorError:
                If communication or response validation fails.
        """
        endpoint = self.RECENT_URLS_ENDPOINT

        if limit is not None:
            normalized_limit = self._validate_limit(limit)
            endpoint = (
                f"{self.RECENT_URLS_ENDPOINT}"
                f"limit/{normalized_limit}/"
            )

        return self._get(endpoint)

    def fetch_url_information(
        self,
        url: str,
    ) -> Dict[str, Any]:
        """
        Retrieve detailed information about a malware URL.

        The detailed response may contain payload hashes,
        malware signatures, file information, VirusTotal
        information, last_online and takedown information.

        Args:
            url:
                Malware URL to query.

        Returns:
            Raw URLhaus JSON response.
        """
        normalized_url = self._validate_non_empty_string(
            value=url,
            field_name="url",
        )

        return self._post(
            self.URL_INFORMATION_ENDPOINT,
            data={"url": normalized_url},
        )

    def fetch_url_information_by_id(
        self,
        urlhaus_id: str | int,
    ) -> Dict[str, Any]:
        """
        Retrieve detailed URL information using its URLhaus ID.

        Args:
            urlhaus_id:
                URLhaus database identifier.

        Returns:
            Raw URLhaus JSON response.
        """
        normalized_id = str(urlhaus_id).strip()

        if not normalized_id:
            raise ValueError(
                "URLhaus ID must not be empty."
            )

        if not normalized_id.isdigit():
            raise ValueError(
                "URLhaus ID must contain only digits."
            )

        return self._post(
            self.URL_ID_INFORMATION_ENDPOINT,
            data={"urlid": normalized_id},
        )

    def fetch_host_information(
        self,
        host: str,
    ) -> Dict[str, Any]:
        """
        Retrieve information about a hostname, domain or IP address.

        Args:
            host:
                IPv4 address, IPv6 address, hostname or domain.

        Returns:
            Raw URLhaus JSON response.
        """
        normalized_host = self._validate_non_empty_string(
            value=host,
            field_name="host",
        )

        return self._post(
            self.HOST_INFORMATION_ENDPOINT,
            data={"host": normalized_host},
        )

    def fetch_recent_payloads(
        self,
        limit: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Retrieve recent payloads observed by URLhaus.

        Args:
            limit:
                Optional number of payloads, between 1 and 1000.

        Returns:
            Raw URLhaus JSON response.
        """
        endpoint = self.RECENT_PAYLOADS_ENDPOINT

        if limit is not None:
            normalized_limit = self._validate_limit(limit)
            endpoint = (
                f"{self.RECENT_PAYLOADS_ENDPOINT}"
                f"limit/{normalized_limit}/"
            )

        return self._get(endpoint)

    def fetch_payload_information(
        self,
        *,
        md5_hash: Optional[str] = None,
        sha256_hash: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Retrieve information about a URLhaus malware payload.

        Exactly one of md5_hash or sha256_hash must be supplied.

        Args:
            md5_hash:
                32-character MD5 hexadecimal digest.

            sha256_hash:
                64-character SHA-256 hexadecimal digest.

        Returns:
            Raw URLhaus JSON response.
        """
        supplied_hashes = [
            value
            for value in (md5_hash, sha256_hash)
            if value is not None
        ]

        if len(supplied_hashes) != 1:
            raise ValueError(
                "Provide exactly one of md5_hash or sha256_hash."
            )

        if md5_hash is not None:
            normalized_hash = self._validate_hash(
                value=md5_hash,
                expected_length=32,
                field_name="md5_hash",
            )

            payload = {
                "md5_hash": normalized_hash,
            }

        else:
            normalized_hash = self._validate_hash(
                value=sha256_hash,
                expected_length=64,
                field_name="sha256_hash",
            )

            payload = {
                "sha256_hash": normalized_hash,
            }

        return self._post(
            self.PAYLOAD_INFORMATION_ENDPOINT,
            data=payload,
        )

    # ============================================================
    # HTTP helpers
    # ============================================================

    def _get(
        self,
        endpoint: str,
    ) -> Dict[str, Any]:
        url = self._build_url(endpoint)

        try:
            response = self._session.get(
                url,
                headers=self._headers,
                timeout=self._timeout,
            )
        except requests.Timeout as exc:
            raise URLhausHTTPError(
                f"URLhaus GET request timed out: {url}"
            ) from exc
        except requests.RequestException as exc:
            raise URLhausHTTPError(
                f"URLhaus GET request failed: {url}"
            ) from exc

        return self._process_response(response)

    def _post(
        self,
        endpoint: str,
        *,
        data: Dict[str, str],
    ) -> Dict[str, Any]:
        url = self._build_url(endpoint)

        try:
            response = self._session.post(
                url,
                headers=self._headers,
                data=data,
                timeout=self._timeout,
            )
        except requests.Timeout as exc:
            raise URLhausHTTPError(
                f"URLhaus POST request timed out: {url}"
            ) from exc
        except requests.RequestException as exc:
            raise URLhausHTTPError(
                f"URLhaus POST request failed: {url}"
            ) from exc

        return self._process_response(response)

    def _process_response(
        self,
        response: Response,
    ) -> Dict[str, Any]:
        """
        Validate the HTTP and JSON-level URLhaus response.
        """
        if response.status_code in {401, 403}:
            raise URLhausAuthenticationError(
                "URLhaus rejected the Auth-Key."
            )

        try:
            response.raise_for_status()
        except requests.HTTPError as exc:
            response_preview = self._response_preview(response)

            raise URLhausHTTPError(
                "URLhaus returned HTTP "
                f"{response.status_code}: {response_preview}"
            ) from exc
        try:
            payload = response.json()
        except ValueError as exc:
            response_preview = self._response_preview(
                response
            )

            raise URLhausResponseError(
                "URLhaus returned invalid JSON: "
                f"{response_preview}"
            ) from exc

        if not isinstance(payload, dict):
            raise URLhausResponseError(
                "URLhaus response root must be a JSON object."
            )

        query_status = payload.get("query_status")

        if not isinstance(query_status, str):
            raise URLhausResponseError(
                "URLhaus response does not contain a valid "
                "'query_status' field."
            )

        if query_status == self.SUCCESS_QUERY_STATUS:
            return payload

        if query_status == self.EMPTY_QUERY_STATUS:
            # A valid empty query is not a transport error.
            return payload

        raise URLhausQueryError(
            "URLhaus query failed with query_status="
            f"{query_status!r}."
        )

    # ============================================================
    # Validation helpers
    # ============================================================

    def _build_url(
        self,
        endpoint: str,
    ) -> str:
        normalized_endpoint = endpoint.strip()

        if not normalized_endpoint:
            raise ValueError(
                "URLhaus endpoint must not be empty."
            )

        if not normalized_endpoint.startswith("/"):
            normalized_endpoint = f"/{normalized_endpoint}"

        return f"{self._base_url}{normalized_endpoint}"

    def _validate_limit(
        self,
        limit: int,
    ) -> int:
        if isinstance(limit, bool) or not isinstance(limit, int):
            raise ValueError(
                "URLhaus limit must be an integer."
            )

        if not 1 <= limit <= self.MAX_RECENT_LIMIT:
            raise ValueError(
                "URLhaus limit must be between 1 and "
                f"{self.MAX_RECENT_LIMIT}."
            )

        return limit

    @staticmethod
    def _validate_non_empty_string(
        *,
        value: str,
        field_name: str,
    ) -> str:
        if not isinstance(value, str):
            raise TypeError(
                f"{field_name} must be a string."
            )

        normalized_value = value.strip()

        if not normalized_value:
            raise ValueError(
                f"{field_name} must not be empty."
            )

        return normalized_value

    @staticmethod
    def _validate_hash(
        *,
        value: Optional[str],
        expected_length: int,
        field_name: str,
    ) -> str:
        if not isinstance(value, str):
            raise TypeError(
                f"{field_name} must be a string."
            )

        normalized_value = value.strip().lower()

        if len(normalized_value) != expected_length:
            raise ValueError(
                f"{field_name} must contain exactly "
                f"{expected_length} hexadecimal characters."
            )

        try:
            int(normalized_value, 16)
        except ValueError as exc:
            raise ValueError(
                f"{field_name} must be hexadecimal."
            ) from exc

        return normalized_value

    @staticmethod
    def _response_preview(
        response: Response,
        max_length: int = 500,
    ) -> str:
        try:
            text = response.text
        except Exception:
            return "<unavailable response body>"

        if not text:
            return "<empty response body>"

        normalized_text = text.replace("\n", " ").strip()

        if len(normalized_text) > max_length:
            return normalized_text[:max_length] + "..."

        return normalized_text