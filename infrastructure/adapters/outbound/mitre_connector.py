from typing import List, Dict, Optional
import requests
import re
import logging


logger = logging.getLogger(__name__)


class MITREConnector:
    """
    Outbound adapter responsible for communicating with MITRE CVE List.

    Retrieves raw CVE JSON records only.
    Mapping to Threat entities is handled by MITREThreatSource.
    """


    BASE_URL = "https://api.github.com"

    OWNER = "CVEProject"
    REPO = "cvelistV5"

    RAW_URL = (
        "https://raw.githubusercontent.com/"
        "CVEProject/cvelistV5/main/"
    )

    TIMEOUT = 10

    CVE_PATTERN = re.compile(
        r"CVE-\d{4}-\d+\.json$"
    )


    def __init__(self):

        self.session = requests.Session()

        self.session.headers.update(
            {
                "Accept": "application/vnd.github+json",
                "User-Agent": "Threat-Intelligence-Engine"
            }
        )



    def get_latest_commit(self) -> str:
        """
        Retrieves the latest commit SHA from MITRE repository.
        """


        url = (
            f"{self.BASE_URL}/repos/"
            f"{self.OWNER}/{self.REPO}/commits"
        )


        response = self.session.get(
            url,
            params={
                "per_page": 1
            },
            timeout=self.TIMEOUT
        )


        response.raise_for_status()


        commits = response.json()


        if not commits:

            raise RuntimeError(
                "Unable to retrieve MITRE latest commit"
            )


        return commits[0]["sha"]



    def get_changed_files(
        self,
        old_commit: str,
        new_commit: str
    ) -> List[str]:
        """
        Retrieves modified CVE JSON files
        between two Git commits.
        """


        url = (
            f"{self.BASE_URL}/repos/"
            f"{self.OWNER}/{self.REPO}/compare/"
            f"{old_commit}...{new_commit}"
        )


        response = self.session.get(
            url,
            timeout=self.TIMEOUT
        )


        response.raise_for_status()


        files = response.json().get(
            "files",
            []
        )


        changed_files = []


        for file in files:

            filename = file.get(
                "filename"
            )


            if (
                filename
                and filename.startswith("cves/")
                and self.CVE_PATTERN.search(filename)
            ):

                changed_files.append(filename)


        return changed_files



    def download_cve_record(
        self,
        filepath: str
    ) -> Dict:
        """
        Downloads one CVE JSON record from MITRE repository.
        """


        url = (
            self.RAW_URL +
            filepath
        )


        response = self.session.get(
            url,
            timeout=self.TIMEOUT
        )


        response.raise_for_status()


        data = response.json()


        if not isinstance(data, dict):

            raise ValueError(
                f"Invalid MITRE CVE format for {filepath}"
            )


        return data



    def fetch_new_records(
        self,
        old_commit: Optional[str]
    ) -> tuple[str, List[Dict]]:
        """
        Retrieves new or modified CVE records
        since the last synchronization.

        Returns:
            new_commit:
                Latest MITRE repository commit.

            records:
                List of raw CVE JSON records.
        """


        new_commit = self.get_latest_commit()



        # First synchronization:
        # initialize monitoring without importing
        # the complete MITRE history.
        if old_commit is None:

            return new_commit, []



        # No changes since last synchronization.
        if old_commit == new_commit:

            return new_commit, []



        changed_files = self.get_changed_files(
            old_commit,
            new_commit
        )


        records = []


        for filepath in changed_files:

            try:

                record = self.download_cve_record(
                    filepath
                )

                records.append(record)


            except requests.RequestException as error:

                logger.warning(
                    "Failed downloading %s: %s",
                    filepath,
                    error
                )


        return new_commit, records