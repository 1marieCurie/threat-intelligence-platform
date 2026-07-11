from __future__ import annotations

from typing import Any

import requests


class GitHubAdvisoryConnectorError(Exception):
    """Raised when the GitHub Advisory API cannot be queried correctly."""


class GitHubAdvisoryConnector:
    """
    Outbound adapter responsible for collecting raw security advisories
    from the GitHub Global Security Advisories REST API.

    This connector returns raw dictionaries. Mapping the response to
    domain objects is the responsibility of the application service.
    """

    BASE_URL = "https://api.github.com/advisories"
    API_VERSION = "2022-11-28"

    ALLOWED_TYPES = {
        "reviewed",
        "unreviewed",
        "malware",
    }

    ALLOWED_ECOSYSTEMS = {
        "rubygems",
        "npm",
        "pip",
        "maven",
        "nuget",
        "composer",
        "go",
        "rust",
        "erlang",
        "actions",
        "pub",
        "other",
        "swift",
    }

    ALLOWED_SEVERITIES = {
        "unknown",
        "low",
        "medium",
        "high",
        "critical",
    }

    ALLOWED_DIRECTIONS = {
        "asc",
        "desc",
    }

    ALLOWED_SORT_FIELDS = {
        "updated",
        "published",
        "epss_percentage",
        "epss_percentile",
    }

    def __init__(
        self,
        token: str | None = None,
        timeout: float = 30.0,
        session: requests.Session | None = None,
    ) -> None:
        """
        Initialize the connector.

        Args:
            token:
                Optional GitHub token. Public advisories can be collected
                without authentication, but authentication provides a higher
                API rate limit.

            timeout:
                Maximum request duration in seconds.

            session:
                Optional requests session. Useful for connection reuse
                and unit testing.
        """

        if timeout <= 0:
            raise ValueError("timeout must be greater than zero.")

        self.timeout = timeout
        self.session = session or requests.Session()

        self.headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": self.API_VERSION,
            "User-Agent": "threat-intelligence-engine",
        }

        if token:
            self.headers["Authorization"] = f"Bearer {token}"

    def fetch_advisories(
        self,
        *,
        ghsa_id: str | None = None,
        advisory_type: str = "reviewed",
        cve_id: str | None = None,
        ecosystem: str | None = None,
        severity: str | None = None,
        cwes: list[str | int] | None = None,
        is_withdrawn: bool | None = None,
        affects: list[str] | None = None,
        published: str | None = None,
        updated: str | None = None,
        modified: str | None = None,
        epss_percentage: str | None = None,
        epss_percentile: str | None = None,
        direction: str = "desc",
        sort: str = "published",
        per_page: int = 30,
        before: str | None = None,
        after: str | None = None,
        max_pages: int | None = 1,
    ) -> list[dict[str, Any]]:
        """
        Collect GitHub global security advisories.

        Args:
            ghsa_id:
                Return only the advisory matching this GHSA identifier.

            advisory_type:
                One of: reviewed, unreviewed, malware.

            cve_id:
                Return only advisories matching this CVE identifier.

            ecosystem:
                Package ecosystem such as npm, pip, maven or composer.

            severity:
                One of: unknown, low, medium, high, critical.

            cwes:
                CWE identifiers. Both "CWE-79" and 79 are accepted.

            is_withdrawn:
                When provided, filters advisories by withdrawal status.

            affects:
                Package names or package@version expressions.

            published:
                GitHub date or date-range search expression.

            updated:
                Filter based on the advisory update date.

            modified:
                Filter advisories published or updated in the specified range.

            epss_percentage:
                EPSS percentage search expression.

            epss_percentile:
                EPSS percentile search expression.

            direction:
                asc or desc.

            sort:
                updated, published, epss_percentage or epss_percentile.

            per_page:
                Number of results per page, between 1 and 100.

            before:
                Pagination cursor returned by GitHub.

            after:
                Pagination cursor returned by GitHub.

            max_pages:
                Maximum number of pages to collect.
                Use 1 for one page.
                Use None to follow every available page.

        Returns:
            A list containing raw GitHub advisory dictionaries.

        Raises:
            ValueError:
                When a parameter is invalid.

            GitHubAdvisoryConnectorError:
                When the API call fails or returns an unexpected response.
        """

        self._validate_parameters(
            advisory_type=advisory_type,
            ecosystem=ecosystem,
            severity=severity,
            direction=direction,
            sort=sort,
            per_page=per_page,
            max_pages=max_pages,
            affects=affects,
        )

        params = self._build_params(
            ghsa_id=ghsa_id,
            advisory_type=advisory_type,
            cve_id=cve_id,
            ecosystem=ecosystem,
            severity=severity,
            cwes=cwes,
            is_withdrawn=is_withdrawn,
            affects=affects,
            published=published,
            updated=updated,
            modified=modified,
            epss_percentage=epss_percentage,
            epss_percentile=epss_percentile,
            direction=direction,
            sort=sort,
            per_page=per_page,
            before=before,
            after=after,
        )

        advisories: list[dict[str, Any]] = []
        next_url: str | None = self.BASE_URL
        current_params: dict[str, Any] | None = params
        pages_collected = 0

        while next_url is not None:
            if max_pages is not None and pages_collected >= max_pages:
                break

            response = self._send_request(
                url=next_url,
                params=current_params,
            )

            payload = self._read_payload(response)

            advisories.extend(payload)
            pages_collected += 1

            # The next URL already contains its pagination parameters.
            next_url = response.links.get("next", {}).get("url")
            current_params = None

        return advisories

    def fetch_advisory_by_ghsa_id(
        self,
        ghsa_id: str,
    ) -> dict[str, Any] | None:
        """
        Retrieve one advisory using its GHSA identifier.

        Returns None if GitHub does not return a matching advisory.
        """

        if not ghsa_id or not ghsa_id.strip():
            raise ValueError("ghsa_id must not be empty.")

        advisories = self.fetch_advisories(
            ghsa_id=ghsa_id.strip(),
            max_pages=1,
        )

        if not advisories:
            return None

        return advisories[0]

    def fetch_advisories_by_cve_id(
        self,
        cve_id: str,
    ) -> list[dict[str, Any]]:
        """
        Retrieve advisories associated with a CVE identifier.
        """

        if not cve_id or not cve_id.strip():
            raise ValueError("cve_id must not be empty.")

        return self.fetch_advisories(
            cve_id=cve_id.strip(),
            max_pages=None,
        )

    def fetch_modified_advisories(
        self,
        modified: str,
        *,
        advisory_type: str = "reviewed",
        per_page: int = 100,
        max_pages: int | None = None,
    ) -> list[dict[str, Any]]:
        """
        Retrieve advisories published or updated during a date range.

        Example:
            modified="2026-07-01..2026-07-10"
        """

        if not modified or not modified.strip():
            raise ValueError("modified must not be empty.")

        return self.fetch_advisories(
            advisory_type=advisory_type,
            modified=modified.strip(),
            sort="updated",
            direction="asc",
            per_page=per_page,
            max_pages=max_pages,
        )

    def _send_request(
        self,
        *,
        url: str,
        params: dict[str, Any] | None,
    ) -> requests.Response:
        try:
            response = self.session.get(
                url,
                headers=self.headers,
                params=params,
                timeout=self.timeout,
            )

            response.raise_for_status()

            return response

        except requests.Timeout as exc:
            raise GitHubAdvisoryConnectorError(
                "GitHub Advisory API request timed out."
            ) from exc

        except requests.HTTPError as exc:
            status_code = (
                exc.response.status_code
                if exc.response is not None
                else "unknown"
            )

            message = self._extract_error_message(exc.response)

            raise GitHubAdvisoryConnectorError(
                "GitHub Advisory API returned an HTTP error. "
                f"Status: {status_code}. Message: {message}"
            ) from exc

        except requests.RequestException as exc:
            raise GitHubAdvisoryConnectorError(
                f"Unable to contact GitHub Advisory API: {exc}"
            ) from exc

    @staticmethod
    def _read_payload(
        response: requests.Response,
    ) -> list[dict[str, Any]]:
        try:
            payload = response.json()
        except ValueError as exc:
            raise GitHubAdvisoryConnectorError(
                "GitHub Advisory API returned invalid JSON."
            ) from exc

        if not isinstance(payload, list):
            raise GitHubAdvisoryConnectorError(
                "Unexpected GitHub Advisory API response: "
                "a JSON array was expected."
            )

        if not all(isinstance(item, dict) for item in payload):
            raise GitHubAdvisoryConnectorError(
                "Unexpected GitHub Advisory API response: "
                "every advisory must be a JSON object."
            )

        return payload

    @staticmethod
    def _extract_error_message(
        response: requests.Response | None,
    ) -> str:
        if response is None:
            return "No response details available."

        try:
            payload = response.json()

            if isinstance(payload, dict):
                message = payload.get("message")

                if message:
                    return str(message)

        except ValueError:
            pass

        return response.text or "No error message returned."

    @classmethod
    def _validate_parameters(
        cls,
        *,
        advisory_type: str,
        ecosystem: str | None,
        severity: str | None,
        direction: str,
        sort: str,
        per_page: int,
        max_pages: int | None,
        affects: list[str] | None,
    ) -> None:
        if advisory_type not in cls.ALLOWED_TYPES:
            raise ValueError(
                f"Invalid advisory_type: {advisory_type}. "
                f"Expected one of {sorted(cls.ALLOWED_TYPES)}."
            )

        if (
            ecosystem is not None
            and ecosystem not in cls.ALLOWED_ECOSYSTEMS
        ):
            raise ValueError(
                f"Invalid ecosystem: {ecosystem}. "
                f"Expected one of {sorted(cls.ALLOWED_ECOSYSTEMS)}."
            )

        if severity is not None and severity not in cls.ALLOWED_SEVERITIES:
            raise ValueError(
                f"Invalid severity: {severity}. "
                f"Expected one of {sorted(cls.ALLOWED_SEVERITIES)}."
            )

        if direction not in cls.ALLOWED_DIRECTIONS:
            raise ValueError(
                f"Invalid direction: {direction}. "
                f"Expected one of {sorted(cls.ALLOWED_DIRECTIONS)}."
            )

        if sort not in cls.ALLOWED_SORT_FIELDS:
            raise ValueError(
                f"Invalid sort field: {sort}. "
                f"Expected one of {sorted(cls.ALLOWED_SORT_FIELDS)}."
            )

        if not 1 <= per_page <= 100:
            raise ValueError("per_page must be between 1 and 100.")

        if max_pages is not None and max_pages < 1:
            raise ValueError(
                "max_pages must be greater than or equal to 1, or None."
            )

        if affects is not None:
            if len(affects) > 1000:
                raise ValueError(
                    "affects cannot contain more than 1000 packages."
                )

            if any(not value.strip() for value in affects):
                raise ValueError(
                    "affects cannot contain empty package names."
                )

    @staticmethod
    def _build_params(
        *,
        ghsa_id: str | None,
        advisory_type: str,
        cve_id: str | None,
        ecosystem: str | None,
        severity: str | None,
        cwes: list[str | int] | None,
        is_withdrawn: bool | None,
        affects: list[str] | None,
        published: str | None,
        updated: str | None,
        modified: str | None,
        epss_percentage: str | None,
        epss_percentile: str | None,
        direction: str,
        sort: str,
        per_page: int,
        before: str | None,
        after: str | None,
    ) -> dict[str, Any]:
        params: dict[str, Any] = {
            "type": advisory_type,
            "direction": direction,
            "sort": sort,
            "per_page": per_page,
        }

        optional_params = {
            "ghsa_id": ghsa_id,
            "cve_id": cve_id,
            "ecosystem": ecosystem,
            "severity": severity,
            "published": published,
            "updated": updated,
            "modified": modified,
            "epss_percentage": epss_percentage,
            "epss_percentile": epss_percentile,
            "before": before,
            "after": after,
        }

        for key, value in optional_params.items():
            if value is not None:
                params[key] = value

        if cwes:
            params["cwes"] = ",".join(
                GitHubAdvisoryConnector._normalize_cwe(cwe)
                for cwe in cwes
            )

        if affects:
            params["affects"] = ",".join(affects)

        if is_withdrawn is not None:
            params["is_withdrawn"] = (
                "true" if is_withdrawn else "false"
            )

        return params

    @staticmethod
    def _normalize_cwe(cwe: str | int) -> str:
        """
        Convert 79 or 'CWE-79' to '79', as expected by the API filter.
        """

        normalized = str(cwe).strip().upper()

        if normalized.startswith("CWE-"):
            normalized = normalized[4:]

        if not normalized.isdigit():
            raise ValueError(
                f"Invalid CWE identifier: {cwe}. "
                "Expected a value such as 79 or CWE-79."
            )

        return normalized