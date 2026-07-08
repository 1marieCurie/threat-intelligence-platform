import requests
from typing import Dict


class CISAConnector:
    """
    Outbound Adapter

    Handles communication with the CISA KEV feed.
    """

    KEV_URL = (
        "https://www.cisa.gov/sites/default/files/feeds/"
        "known_exploited_vulnerabilities.json"
    )

    def fetch(self) -> Dict:
        """
        Retrieve the complete CISA Known Exploited Vulnerabilities catalog.

        Returns:
            dict: Raw JSON response from CISA.
        """

        response = requests.get(self.KEV_URL)

        response.raise_for_status()

        return response.json()