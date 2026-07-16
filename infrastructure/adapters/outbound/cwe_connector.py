from __future__ import annotations

import re
from typing import Any, Iterable

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


class CWEConnector:
    """
    Outbound adapter responsible for communicating with the
    official MITRE CWE REST API.

    Responsibilities:
    - retrieve the current CWE catalog version;
    - retrieve one or several CWE weakness entries;
    - retrieve the complete weakness catalog;
    - retrieve CWE entry metadata;
    - retrieve optional hierarchy relationships;
    - validate the basic shape of API responses.

    This connector returns raw dictionaries and lists only.
    Conversion to CWEWeakness domain objects belongs to the
    application service.
    """

    BASE_URL = "https://cwe-api.mitre.org/api/v1"

    TIMEOUT = 30

    # Smaller batches reduce response sizes and make retries cheaper.
    MAX_IDS_PER_REQUEST = 50

    CWE_ID_PATTERN = re.compile(
        r"^(?:CWE-)?(\d+)$",
        re.IGNORECASE,
    )

    def __init__(
        self,
        session: requests.Session | None = None,
        *,
        timeout: int | float = TIMEOUT,
    ) -> None:
        """
        Create the connector.

        A custom requests.Session can be injected for unit tests.
        """

        if isinstance(timeout, bool):
            raise ValueError(
                "timeout must be greater than zero."
            )

        if not isinstance(timeout, (int, float)):
            raise TypeError(
                "timeout must be an integer or float."
            )

        if timeout <= 0:
            raise ValueError(
                "timeout must be greater than zero."
            )

        self.timeout = timeout

        if session is not None:
            self.session = session
        else:
            self.session = self._build_session()

        self.session.headers.update(
            {
                "Accept": "application/json",
                "User-Agent": (
                    "Threat-Intelligence-Engine/1.0"
                ),
            }
        )

    # =========================================================
    # Public catalog operations
    # =========================================================

    def fetch_version(
        self,
    ) -> dict[str, Any]:
        """
        Retrieve the current CWE catalog version metadata.

        Official endpoint:
            GET /cwe/version
        """

        payload = self._get_json(
            "/cwe/version"
        )

        if not isinstance(payload, dict):
            raise ValueError(
                "Invalid CWE version response: "
                "expected a JSON object."
            )

        return payload

    def fetch_all_weaknesses(
        self,
        *,
        attempts: int = 2,
    ) -> dict[str, Any]:
        """
        Retrieve all official CWE weakness entries.

        Official endpoint:
            GET /cwe/weakness/all

        This endpoint returns a very large JSON response. A network
        intermediary or the remote server may occasionally return
        a truncated body despite HTTP 200. A limited retry is used
        for this operation.

        Expected response shape:
            {
                "Weaknesses": [...]
            }
        """

        if isinstance(attempts, bool):
            raise ValueError(
                "attempts must be greater than zero."
            )

        if not isinstance(attempts, int):
            raise TypeError(
                "attempts must be an integer."
            )

        if attempts <= 0:
            raise ValueError(
                "attempts must be greater than zero."
            )

        last_error: Exception | None = None

        for _ in range(attempts):
            try:
                payload = self._get_json(
                    "/cwe/weakness/all"
                )

                self._validate_weakness_response(
                    payload
                )

                return payload

            except (
                requests.RequestException,
                ConnectionError,
                ValueError,
            ) as error:
                last_error = error

        raise ValueError(
            "Unable to retrieve a complete CWE catalog "
            f"after {attempts} attempt(s)."
        ) from last_error

    def fetch_weakness(
        self,
        cwe_id: str | int,
    ) -> dict[str, Any]:
        """
        Retrieve one official CWE weakness.

        Accepted identifier formats:
            79
            "79"
            "CWE-79"
            "00079"
            "CWE-00079"

        The API response contains a Weaknesses list.
        """

        normalized_id = self._normalize_cwe_id(
            cwe_id
        )

        payload = self._get_json(
            f"/cwe/weakness/{normalized_id}"
        )

        self._validate_weakness_response(
            payload
        )

        weaknesses = payload["Weaknesses"]

        if not weaknesses:
            raise ValueError(
                f"CWE-{normalized_id} was not returned "
                "by the CWE API."
            )

        return payload

    def fetch_weaknesses(
        self,
        cwe_ids: Iterable[str | int],
    ) -> dict[str, Any]:
        """
        Retrieve several CWE weaknesses.

        The official API accepts comma-separated identifiers:

            GET /cwe/weakness/79,89,502

        Large collections are split into batches and merged while
        preserving the API response order.
        """

        normalized_ids = (
            self._normalize_cwe_ids(
                cwe_ids
            )
        )

        if not normalized_ids:
            return {
                "Weaknesses": [],
            }

        weaknesses: list[dict[str, Any]] = []
        seen_ids: set[str] = set()

        for batch in self._chunked(
            normalized_ids,
            self.MAX_IDS_PER_REQUEST,
        ):
            joined_ids = ",".join(batch)

            payload = self._get_json(
                f"/cwe/weakness/{joined_ids}"
            )

            self._validate_weakness_response(
                payload
            )

            for weakness in payload["Weaknesses"]:
                raw_id = weakness.get("ID")

                normalized_response_id = (
                    self._normalize_response_cwe_id(
                        raw_id
                    )
                )

                # If the server response has no usable ID, preserve
                # the item using a deterministic fallback key.
                if normalized_response_id is None:
                    deduplication_key = repr(
                        weakness
                    )
                else:
                    deduplication_key = (
                        normalized_response_id
                    )

                if deduplication_key in seen_ids:
                    continue

                weaknesses.append(weakness)
                seen_ids.add(
                    deduplication_key
                )

        return {
            "Weaknesses": weaknesses,
        }

    # =========================================================
    # CWE metadata
    # =========================================================

    def fetch_cwe_metadata(
        self,
        cwe_ids: Iterable[str | int],
    ) -> list[dict[str, Any]]:
        """
        Retrieve metadata for one or several CWE IDs.

        Official endpoint:
            GET /cwe/{ids}

        The endpoint returns a JSON list, including when only one
        identifier is requested.
        """

        normalized_ids = (
            self._normalize_cwe_ids(
                cwe_ids
            )
        )

        if not normalized_ids:
            raise ValueError(
                "At least one CWE identifier is required."
            )

        joined_ids = ",".join(
            normalized_ids
        )

        payload = self._get_json(
            f"/cwe/{joined_ids}"
        )

        return self._validate_metadata_response(
            payload
        )

    # =========================================================
    # Relationship endpoints
    # =========================================================

    def fetch_parents(
        self,
        cwe_id: str | int,
        *,
        view: str | int | None = None,
    ) -> list[dict[str, Any]]:
        """
        Retrieve direct parents of a CWE entry.

        Official endpoint:
            GET /cwe/{id}/parents
        """

        return self._fetch_relationships(
            cwe_id=cwe_id,
            relationship="parents",
            view=view,
        )

    def fetch_children(
        self,
        cwe_id: str | int,
        *,
        view: str | int | None = None,
    ) -> list[dict[str, Any]]:
        """
        Retrieve direct children of a CWE entry.

        Official endpoint:
            GET /cwe/{id}/children
        """

        return self._fetch_relationships(
            cwe_id=cwe_id,
            relationship="children",
            view=view,
        )

    def fetch_descendants(
        self,
        cwe_id: str | int,
        *,
        view: str | int | None = None,
    ) -> list[dict[str, Any]]:
        """
        Retrieve all descendants of a CWE entry.

        Official endpoint:
            GET /cwe/{id}/descendants
        """

        return self._fetch_relationships(
            cwe_id=cwe_id,
            relationship="descendants",
            view=view,
        )

    def fetch_ancestors(
        self,
        cwe_id: str | int,
        *,
        view: str | int | None = None,
        primary: bool | None = None,
    ) -> list[dict[str, Any]]:
        """
        Retrieve all ancestors of a CWE entry.

        Official endpoint:
            GET /cwe/{id}/ancestors
        """

        normalized_id = self._normalize_cwe_id(
            cwe_id
        )

        params: dict[str, Any] = {}

        if view is not None:
            params["view"] = str(view)

        if primary is not None:
            params["primary"] = primary

        payload = self._get_json(
            f"/cwe/{normalized_id}/ancestors",
            params=params,
        )

        return self._validate_relationship_response(
            payload=payload,
            relationship="ancestors",
        )

    # =========================================================
    # Internal HTTP operations
    # =========================================================

    @staticmethod
    def _build_session(
    ) -> requests.Session:
        """
        Build a requests session with retry support.

        Retries are limited to idempotent GET operations and
        temporary server or rate-limit failures.
        """

        session = requests.Session()

        retry_policy = Retry(
            total=3,
            connect=3,
            read=3,
            status=3,
            backoff_factor=0.5,
            status_forcelist=(
                429,
                500,
                502,
                503,
                504,
            ),
            allowed_methods=frozenset(
                {
                    "GET",
                }
            ),
            raise_on_status=False,
        )

        adapter = HTTPAdapter(
            max_retries=retry_policy,  # type: ignore[arg-type]
        )

        session.mount(
            "https://",
            adapter,
        )

        session.mount(
            "http://",
            adapter,
        )

        return session

    def _get_json(
        self,
        endpoint: str,
        *,
        params: dict[str, Any] | None = None,
    ) -> Any:
        """
        Perform one GET request and return the decoded JSON body.
        """

        if not isinstance(endpoint, str):
            raise TypeError(
                "endpoint must be a string."
            )

        endpoint = endpoint.strip()

        if not endpoint:
            raise ValueError(
                "endpoint cannot be empty."
            )

        if not endpoint.startswith("/"):
            endpoint = f"/{endpoint}"

        url = f"{self.BASE_URL}{endpoint}"

        try:
            response = self.session.get(
                url,
                params=params,
                timeout=self.timeout,
            )

        except requests.RequestException:
            # Keep the original requests exception type so callers
            # can distinguish timeout, connection and transport errors.
            raise

        try:
            response.raise_for_status()

        except requests.HTTPError as error:
            status_code = response.status_code

            if status_code == 404:
                raise LookupError(
                    "CWE API resource not found: "
                    f"{url}"
                ) from error

            raise ConnectionError(
                "CWE API request failed with "
                f"HTTP status {status_code}: {url}"
            ) from error

        try:
            return response.json()

        except requests.JSONDecodeError as error:
            raise ValueError(
                "CWE API returned an invalid JSON response "
                f"for {url}."
            ) from error

    # =========================================================
    # Response validation
    # =========================================================

    @staticmethod
    def _validate_weakness_response(
        payload: Any,
    ) -> None:
        """
        Validate the basic CWE weakness response structure.
        """

        if not isinstance(payload, dict):
            raise ValueError(
                "Invalid CWE weakness response: "
                "expected a JSON object."
            )

        weaknesses = payload.get(
            "Weaknesses"
        )

        if not isinstance(weaknesses, list):
            raise ValueError(
                "Invalid CWE weakness response: "
                "missing Weaknesses list."
            )

        for weakness in weaknesses:
            if not isinstance(
                weakness,
                dict,
            ):
                raise ValueError(
                    "Invalid CWE weakness response: "
                    "every Weaknesses element must "
                    "be a JSON object."
                )

    @staticmethod
    def _validate_metadata_response(
        payload: Any,
    ) -> list[dict[str, Any]]:
        """
        Validate a generic CWE metadata response.
        """

        if not isinstance(payload, list):
            raise ValueError(
                "Invalid CWE metadata response: "
                "expected a JSON list."
            )

        result: list[dict[str, Any]] = []

        for item in payload:
            if not isinstance(item, dict):
                raise ValueError(
                    "Invalid CWE metadata response: "
                    "every element must be a JSON object."
                )

            result.append(item)

        return result

    @staticmethod
    def _validate_relationship_response(
        *,
        payload: Any,
        relationship: str,
    ) -> list[dict[str, Any]]:
        """
        Validate a hierarchy endpoint response.

        MITRE returns an empty list when the CWE entry exists but
        has no matching relationship.
        """

        if not isinstance(payload, list):
            raise ValueError(
                "Invalid CWE "
                f"{relationship} response: "
                "expected a JSON list."
            )

        result: list[dict[str, Any]] = []

        for item in payload:
            if not isinstance(item, dict):
                raise ValueError(
                    "Invalid CWE "
                    f"{relationship} response: "
                    "every element must be a JSON object."
                )

            result.append(item)

        return result

    def _fetch_relationships(
        self,
        *,
        cwe_id: str | int,
        relationship: str,
        view: str | int | None,
    ) -> list[dict[str, Any]]:
        """
        Shared implementation for parent, child and descendant
        relationship endpoints.
        """

        allowed_relationships = {
            "parents",
            "children",
            "descendants",
        }

        if relationship not in allowed_relationships:
            raise ValueError(
                f"Unsupported CWE relationship: {relationship}"
            )

        normalized_id = self._normalize_cwe_id(
            cwe_id
        )

        params: dict[str, Any] = {}

        if view is not None:
            params["view"] = str(view)

        payload = self._get_json(
            (
                f"/cwe/{normalized_id}/"
                f"{relationship}"
            ),
            params=params,
        )

        return self._validate_relationship_response(
            payload=payload,
            relationship=relationship,
        )

    # =========================================================
    # Identifier normalization
    # =========================================================

    @classmethod
    def _normalize_cwe_id(
        cls,
        value: str | int,
    ) -> str:
        """
        Normalize a CWE identifier to the numeric representation
        expected in API paths.

        Accepted examples:
            CWE-79      -> 79
            cwe-79      -> 79
            "79"        -> 79
            79          -> 79
            "00079"     -> 79
            "CWE-00079" -> 79
        """

        if isinstance(value, bool):
            raise ValueError(
                "Boolean values are not valid CWE identifiers."
            )

        if isinstance(value, int):
            if value <= 0:
                raise ValueError(
                    "CWE identifier must be greater than zero."
                )

            return str(value)

        if not isinstance(value, str):
            raise TypeError(
                "CWE identifier must be a string or integer."
            )

        normalized = value.strip()

        match = cls.CWE_ID_PATTERN.fullmatch(
            normalized
        )

        if match is None:
            raise ValueError(
                f"Invalid CWE identifier: {value!r}"
            )

        numeric_id = int(
            match.group(1)
        )

        if numeric_id <= 0:
            raise ValueError(
                "CWE identifier must be greater than zero."
            )

        return str(numeric_id)

    @classmethod
    def _normalize_cwe_ids(
        cls,
        values: Iterable[str | int],
    ) -> list[str]:
        """
        Normalize and deduplicate several CWE identifiers while
        preserving their original order.
        """

        if isinstance(
            values,
            (str, bytes),
        ):
            raise TypeError(
                "cwe_ids must be an iterable of identifiers, "
                "not a single string."
            )

        try:
            iterator = iter(values)

        except TypeError as error:
            raise TypeError(
                "cwe_ids must be an iterable of identifiers."
            ) from error

        normalized_ids: list[str] = []
        seen: set[str] = set()

        for value in iterator:
            normalized_id = (
                cls._normalize_cwe_id(
                    value
                )
            )

            if normalized_id in seen:
                continue

            normalized_ids.append(
                normalized_id
            )

            seen.add(normalized_id)

        return normalized_ids

    @classmethod
    def _normalize_response_cwe_id(
        cls,
        value: Any,
    ) -> str | None:
        """
        Normalize an ID received from the CWE API.

        Invalid or missing IDs do not raise because this method is
        used only to build a deduplication key for returned records.
        """

        try:
            return cls._normalize_cwe_id(
                value
            )

        except (
            TypeError,
            ValueError,
        ):
            return None

    # =========================================================
    # Batching
    # =========================================================

    @staticmethod
    def _chunked(
        values: list[str],
        size: int,
    ) -> Iterable[list[str]]:
        """
        Yield fixed-size batches.
        """

        if isinstance(size, bool):
            raise ValueError(
                "Chunk size must be greater than zero."
            )

        if not isinstance(size, int):
            raise TypeError(
                "Chunk size must be an integer."
            )

        if size <= 0:
            raise ValueError(
                "Chunk size must be greater than zero."
            )

        for index in range(
            0,
            len(values),
            size,
        ):
            yield values[
                index:index + size
            ]