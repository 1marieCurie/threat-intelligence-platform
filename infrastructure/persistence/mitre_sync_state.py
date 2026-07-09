import json
from pathlib import Path
from typing import Optional


class MITRESyncState:
    """
    Handles persistence of MITRE synchronization state.

    Stores the last processed Git commit SHA
    to allow incremental CVE ingestion.
    """


    def __init__(
        self,
        filepath: str = "infrastructure/persistence/mitre_sync_state.json"
    ):
        self.filepath = Path(filepath)



    def get_last_commit(self) -> Optional[str]:
        """
        Retrieves the last processed MITRE commit SHA.

        Returns:
            The commit SHA if available,
            otherwise None.
        """


        if not self.filepath.exists():

            return None


        try:

            with open(
                self.filepath,
                "r",
                encoding="utf-8"
            ) as file:

                data = json.load(file)


        except json.JSONDecodeError:

            return None



        return data.get("last_commit")



    def save_last_commit(
        self,
        commit_sha: str
    ):
        """
        Saves the latest processed MITRE commit SHA.
        """


        self.filepath.parent.mkdir(
            parents=True,
            exist_ok=True
        )


        with open(
            self.filepath,
            "w",
            encoding="utf-8"
        ) as file:

            json.dump(
                {
                    "last_commit": commit_sha
                },
                file,
                indent=4,
                ensure_ascii=False
            )