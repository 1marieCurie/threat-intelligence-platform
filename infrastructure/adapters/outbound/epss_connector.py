from typing import Dict, List, Optional
import requests


class EPSSConnector:
    """
    Outbound adapter responsible for communicating with the FIRST EPSS API.

    EPSS provides exploitation probability scores for CVE identifiers.
    This connector only retrieves raw EPSS JSON data.
    Enrichment of Threat entities is handled by EPSSEnrichmentService.
    """

    BASE_URL = "https://api.first.org/data/v1/epss"

    TIMEOUT = 10

    # FIRST documentation indicates that the 'cve' query parameter
    # supports multiple comma-separated CVE IDs with a maximum size of
    # 2000 characters including commas.
    MAX_CVE_QUERY_LENGTH = 2000

    def __init__(self):
        self.session = requests.Session()

        self.session.headers.update(
            {
                "Accept": "application/json",
                "User-Agent": "Threat-Intelligence-Engine"
            }
        )

    def fetch_by_cve(
        self,
        cve_id: str,
        date: Optional[str] = None
    ) -> Dict:
        """
        Fetches EPSS data for a single CVE.

        Args:
            cve_id:
                CVE identifier, e.g. CVE-2021-44228.

            date:
                Optional historical EPSS date in YYYY-MM-DD format.

        Returns:
            Raw JSON response from FIRST EPSS API.
        """

        return self.fetch_by_cves(
            cve_ids=[cve_id],
            date=date
        )

    def fetch_by_cves(
        self,
        cve_ids: List[str],
        date: Optional[str] = None
    ) -> Dict:
        """
        Fetches EPSS data for multiple CVE identifiers.

        The FIRST EPSS API accepts multiple CVE IDs separated by commas.

        Args:
            cve_ids:
                List of CVE identifiers.

            date:
                Optional historical EPSS date in YYYY-MM-DD format.

        Returns:
            Raw JSON response from FIRST EPSS API.
        """

        cleaned_cve_ids = self._clean_cve_ids(
            cve_ids
        )

        if not cleaned_cve_ids:
            return {
                "status": "OK",
                "status-code": 200,
                "total": 0,
                "data": []
            }

        cve_query = ",".join(
            cleaned_cve_ids
        )

        if len(cve_query) > self.MAX_CVE_QUERY_LENGTH:
            raise ValueError(
                "The CVE query parameter exceeds the FIRST EPSS "
                "maximum size of 2000 characters. Use fetch_by_batches()."
            )

        params = {
            "cve": cve_query
        }

        if date is not None:
            params["date"] = date

        response = self.session.get(
            self.BASE_URL,
            params=params,
            timeout=self.TIMEOUT
        )

        response.raise_for_status()

        data = response.json()

        if not isinstance(data, dict):
            raise ValueError(
                "Invalid EPSS API response format."
            )

        return data

    def fetch_by_batches(
        self,
        cve_ids: List[str],
        date: Optional[str] = None
    ) -> List[Dict]:
        """
        Fetches EPSS data for a large list of CVEs using several API calls.

        This method respects the EPSS API limitation on the maximum
        length of the 'cve' query parameter.

        Args:
            cve_ids:
                List of CVE identifiers.

            date:
                Optional historical EPSS date in YYYY-MM-DD format.

        Returns:
            A list of raw JSON responses from FIRST EPSS API.
        """

        cleaned_cve_ids = self._clean_cve_ids(
            cve_ids
        )

        batches = self._build_cve_batches(
            cleaned_cve_ids
        )

        responses = []

        for batch in batches:
            response = self.fetch_by_cves(
                cve_ids=batch,
                date=date
            )

            responses.append(response)

        return responses

    def _clean_cve_ids(
        self,
        cve_ids: List[str]
    ) -> List[str]:
        """
        Removes invalid, empty, and duplicated CVE IDs while preserving order.
        """

        cleaned = []
        seen = set()

        for cve_id in cve_ids:

            if not cve_id:
                continue

            normalized = cve_id.strip().upper()

            if not normalized.startswith("CVE-"):
                continue

            if normalized in seen:
                continue

            cleaned.append(normalized)
            seen.add(normalized)

        return cleaned

    def _build_cve_batches(
        self,
        cve_ids: List[str]
    ) -> List[List[str]]:
        """
        Builds CVE batches whose comma-separated query length
        does not exceed the EPSS API limit.
        """

        batches = []
        current_batch = []
        current_length = 0

        for cve_id in cve_ids:

            # If current_batch is not empty, a comma will be added
            # before the next CVE ID.
            additional_length = len(cve_id)

            if current_batch:
                additional_length += 1

            if (
                current_batch
                and current_length + additional_length > self.MAX_CVE_QUERY_LENGTH
            ):
                batches.append(
                    current_batch
                )

                current_batch = [
                    cve_id
                ]

                current_length = len(
                    cve_id
                )

            else:
                current_batch.append(
                    cve_id
                )

                current_length += additional_length

        if current_batch:
            batches.append(
                current_batch
            )

        return batches