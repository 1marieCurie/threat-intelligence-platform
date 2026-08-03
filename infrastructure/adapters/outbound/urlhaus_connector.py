from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

import requests
from requests import (
    Response,
    Session,
)


class URLhausConnectorError(RuntimeError):
    """Erreur de base du connecteur URLhaus."""


class URLhausAuthenticationError(
    URLhausConnectorError
):
    """Clé d'authentification absente ou refusée."""


class URLhausHTTPError(
    URLhausConnectorError
):
    """Erreur de transport ou réponse HTTP invalide."""


class URLhausResponseError(
    URLhausConnectorError
):
    """Réponse JSON URLhaus invalide."""


class URLhausQueryError(
    URLhausConnectorError
):
    """Échec fonctionnel signalé par URLhaus."""


class URLhausConnector:
    """
    Adaptateur HTTP sortant vers URLhaus.

    La clé d'authentification doit être injectée explicitement.
    Le connecteur ne lit jamais directement les variables
    d'environnement.
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

    def __init__(
        self,
        auth_key: str | None,
        *,
        session: Session | None = None,
        timeout: float = DEFAULT_TIMEOUT,
        base_url: str = BASE_URL,
        user_agent: str = (
            "threat-intelligence-engine/0.1"
        ),
    ) -> None:
        normalized_auth_key = (
            self._validate_auth_key(
                auth_key
            )
        )

        normalized_timeout = (
            self._validate_timeout(
                timeout
            )
        )

        normalized_base_url = (
            self._validate_base_url(
                base_url
            )
        )

        normalized_user_agent = (
            self._validate_non_empty_string(
                value=user_agent,
                field_name="user_agent",
            )
        )

        self._timeout = normalized_timeout
        self._base_url = normalized_base_url

        self._session = (
            session
            if session is not None
            else requests.Session()
        )

        self._headers = {
            "Auth-Key": normalized_auth_key,
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
        Retourne l'URL canonique de la collecte récente.

        Cette URL ne contient ni clé d'authentification,
        ni paramètres sensibles.
        """

        return (
            f"{self._base_url}"
            f"{self.RECENT_URLS_ENDPOINT}"
        )

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
                f"{endpoint}"
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
        if isinstance(
            urlhaus_id,
            bool,
        ):
            raise ValueError(
                "URLhaus ID must contain "
                "only digits."
            )

        normalized_id = str(
            urlhaus_id
        ).strip()

        if not normalized_id:
            raise ValueError(
                "URLhaus ID must not be empty."
            )

        if not normalized_id.isdigit():
            raise ValueError(
                "URLhaus ID must contain "
                "only digits."
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
                f"{endpoint}"
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
        supplied_hashes = tuple(
            value
            for value in (
                md5_hash,
                sha256_hash,
            )
            if value is not None
        )

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

            data = {
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

            data = {
                "sha256_hash": normalized_hash,
            }

        return self._post(
            self.PAYLOAD_INFORMATION_ENDPOINT,
            data=data,
        )

    def _get(
        self,
        endpoint: str,
    ) -> dict[str, Any]:
        url = self._build_url(
            endpoint
        )

        try:
            response = self._session.get(
                url,
                headers=dict(
                    self._headers
                ),
                timeout=self._timeout,
            )

        except requests.Timeout:
            raise URLhausHTTPError(
                "URLhaus GET request timed out."
            ) from None

        except requests.RequestException:
            raise URLhausHTTPError(
                "URLhaus GET request failed."
            ) from None

        return self._process_response(
            response
        )

    def _post(
        self,
        endpoint: str,
        *,
        data: dict[str, str],
    ) -> dict[str, Any]:
        url = self._build_url(
            endpoint
        )

        try:
            response = self._session.post(
                url,
                headers=dict(
                    self._headers
                ),
                data=dict(data),
                timeout=self._timeout,
            )

        except requests.Timeout:
            raise URLhausHTTPError(
                "URLhaus POST request timed out."
            ) from None

        except requests.RequestException:
            raise URLhausHTTPError(
                "URLhaus POST request failed."
            ) from None

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

        except requests.HTTPError:
            raise URLhausHTTPError(
                "URLhaus returned HTTP "
                f"{status_code}."
            ) from None

        try:
            payload = response.json()

        except ValueError:
            raise URLhausResponseError(
                "URLhaus returned invalid JSON."
            ) from None

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

        # La valeur fournie par le fournisseur n'est pas
        # réinjectée dans l'exception.
        raise URLhausQueryError(
            "URLhaus query failed."
        )

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

        if any(
            forbidden_value
            in normalized_endpoint
            for forbidden_value in (
                "://",
                "?",
                "#",
            )
        ):
            raise ValueError(
                "URLhaus endpoint is unsafe."
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

    @classmethod
    def _validate_limit(
        cls,
        limit: int,
    ) -> int:
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
            <= cls.MAX_RECENT_LIMIT
        ):
            raise ValueError(
                "URLhaus limit must be "
                "between 1 and "
                f"{cls.MAX_RECENT_LIMIT}."
            )

        return limit

    @staticmethod
    def _validate_auth_key(
        auth_key: str | None,
    ) -> str:
        if not isinstance(
            auth_key,
            str,
        ):
            raise URLhausAuthenticationError(
                "URLhaus Auth-Key is required."
            )

        normalized_auth_key = (
            auth_key.strip()
        )

        if not normalized_auth_key:
            raise URLhausAuthenticationError(
                "URLhaus Auth-Key must "
                "not be empty."
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
                (
                    int,
                    float,
                ),
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
    def _validate_base_url(
        base_url: str,
    ) -> str:
        normalized_base_url = (
            URLhausConnector
            ._validate_non_empty_string(
                value=base_url,
                field_name="base_url",
            )
        )

        parsed_url = urlsplit(
            normalized_base_url
        )

        if parsed_url.scheme.lower() != "https":
            raise ValueError(
                "URLhaus base_url must use HTTPS."
            )

        if parsed_url.hostname is None:
            raise ValueError(
                "URLhaus base_url must contain "
                "a valid hostname."
            )

        if (
            parsed_url.username is not None
            or parsed_url.password is not None
        ):
            raise ValueError(
                "URLhaus base_url must not "
                "contain credentials."
            )

        if parsed_url.query:
            raise ValueError(
                "URLhaus base_url must not "
                "contain a query string."
            )

        if parsed_url.fragment:
            raise ValueError(
                "URLhaus base_url must not "
                "contain a fragment."
            )

        return (
            normalized_base_url.rstrip(
                "/"
            )
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

        except ValueError:
            raise ValueError(
                f"{field_name} must be "
                "hexadecimal."
            ) from None

        return normalized_value