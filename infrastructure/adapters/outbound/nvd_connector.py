import requests


class NVDConnector:
    """
    Outbound Adapter

    Responsible only for communicating with the NVD API.
    No business logic should be implemented here.
    """

    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def fetch(
        self,
        start_date: str,
        end_date: str,
        results_per_page: int = 100,
        start_index: int = 0,
    ) -> dict:
        """
        Fetch CVEs from the NVD API.
        """

        params = {
            "pubStartDate": start_date,
            "pubEndDate": end_date,
            "resultsPerPage": results_per_page,
            "startIndex": start_index,
        }

        response = requests.get(self.BASE_URL, params=params)
        response.raise_for_status()

        return response.json()