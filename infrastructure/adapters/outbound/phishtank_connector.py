# infrastructure/adapters/outbound/phishtank_connector.py

from __future__ import annotations

import bz2
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests


class PhishTankConnectorError(RuntimeError):
    """
    Raised when the PhishTank connector cannot retrieve,
    persist or read the downloadable database.
    """


class PhishTankConnector:
    """
    Outbound adapter responsible for retrieving the PhishTank
    downloadable JSON database.

    Responsibilities:
    - build the PhishTank download URL;
    - check remote metadata using HTTP HEAD;
    - compare the remote ETag with the locally stored ETag;
    - download the compressed JSON snapshot when required;
    - persist synchronization metadata;
    - read raw PhishTank records from the local .bz2 file.

    This connector returns raw dictionaries.

    Mapping raw records to domain Threat objects belongs to
    the application service PhishTankThreatSource.
    """

    PUBLIC_DOWNLOAD_URL = (
        "https://data.phishtank.com/data/"
        "online-valid.json.bz2"
    )

    DEFAULT_DUMP_FILENAME = "online-valid.json.bz2"
    DEFAULT_STATE_FILENAME = "phishtank_sync_state.json"

    def __init__(
        self,
        storage_directory: str | Path = "data/phishtank",
        app_key: Optional[str] = None,
        user_agent: str = (
            "threat-intelligence-engine/1.0"
        ),
        timeout: float = 30.0,
        session: Optional[requests.Session] = None,
    ) -> None:
        """
        Initialize the connector.

        Args:
            storage_directory:
                Directory used to store the compressed dump
                and synchronization metadata.

            app_key:
                Optional PhishTank application key.

                When provided, the download URL becomes:

                https://data.phishtank.com/data/
                <app_key>/online-valid.json.bz2

            user_agent:
                Descriptive HTTP User-Agent required by
                PhishTank.

            timeout:
                HTTP timeout in seconds.

            session:
                Optional requests.Session, useful for tests.
        """

        if timeout <= 0:
            raise ValueError(
                "timeout must be greater than zero."
            )

        normalized_user_agent = user_agent.strip()

        if not normalized_user_agent:
            raise ValueError(
                "user_agent must not be empty."
            )

        normalized_app_key = (
            app_key.strip()
            if isinstance(app_key, str)
            else None
        )

        self.storage_directory = Path(
            storage_directory
        )

        self.dump_path = (
            self.storage_directory
            / self.DEFAULT_DUMP_FILENAME
        )

        self.state_path = (
            self.storage_directory
            / self.DEFAULT_STATE_FILENAME
        )

        self.app_key = normalized_app_key or None
        self.user_agent = normalized_user_agent
        self.timeout = timeout
        self.session = session or requests.Session()

        self.storage_directory.mkdir(
            parents=True,
            exist_ok=True,
        )

    # ============================================================
    # Public API
    # ============================================================

    @property
    def download_url(self) -> str:
        """
        Return the correct PhishTank download URL.
        """

        if self.app_key:
            return (
                "https://data.phishtank.com/data/"
                f"{self.app_key}/"
                "online-valid.json.bz2"
            )

        return self.PUBLIC_DOWNLOAD_URL

    def fetch_raw(
        self,
        *,
        force_download: bool = False,
        limit: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """
        Ensure that a local snapshot exists, then return its
        raw JSON records.

        Args:
            force_download:
                Download the snapshot even if the ETag has
                not changed.

            limit:
                Optional maximum number of records to return.

        Returns:
            Raw PhishTank records.

        Raises:
            PhishTankConnectorError:
                When the snapshot cannot be downloaded or read.
        """

        self.download_if_updated(
            force=force_download
        )

        return self.read_local_records(
            limit=limit
        )

    def download_if_updated(
        self,
        *,
        force: bool = False,
    ) -> Dict[str, Any]:
        """
        Download the current snapshot only when required.

        The file is downloaded when:
        - force=True;
        - no local dump exists;
        - the remote ETag differs from the local ETag;
        - no usable synchronization state exists.

        Returns:
            Synchronization metadata.
        """

        local_state = self._load_state()

        remote_metadata: Dict[str, Any] = {}

        try:
            remote_metadata = self.get_remote_metadata()
        except PhishTankConnectorError:
            # If HEAD fails but a local snapshot exists,
            # preserve availability by using the local file.
            if self.dump_path.exists() and not force:
                return {
                    **local_state,
                    "source": "PHISHTANK",
                    "downloaded": False,
                    "used_local_snapshot": True,
                    "head_request_failed": True,
                    "dump_path": str(self.dump_path),
                }

            # Without a local snapshot, downloading is required.
            remote_metadata = {}

        remote_etag = remote_metadata.get("etag")
        local_etag = local_state.get("etag")

        dump_exists = self.dump_path.exists()

        should_download = (
            force
            or not dump_exists
            or not local_state
            or (
                remote_etag is not None
                and remote_etag != local_etag
            )
        )

        if not should_download:
            return {
                **local_state,
                **remote_metadata,
                "source": "PHISHTANK",
                "downloaded": False,
                "used_local_snapshot": True,
                "dump_path": str(self.dump_path),
            }

        download_metadata = self._download_snapshot()

        state = {
            "source": "PHISHTANK",
            "download_url": self.download_url,
            "etag": (
                download_metadata.get("etag")
                or remote_etag
            ),
            "last_modified": (
                download_metadata.get("last_modified")
                or remote_metadata.get("last_modified")
            ),
            "content_length": (
                download_metadata.get("content_length")
                or remote_metadata.get("content_length")
            ),
            "downloaded_at": (
                datetime.now(timezone.utc).isoformat()
            ),
            "dump_path": str(self.dump_path),
            "downloaded": True,
            "used_local_snapshot": False,
        }

        self._save_state(state)

        return state

    def get_remote_metadata(
        self,
    ) -> Dict[str, Any]:
        """
        Perform an HTTP HEAD request and return remote file
        metadata.
        """

        try:
            response = self.session.head(
                self.download_url,
                headers=self._headers(),
                timeout=self.timeout,
                allow_redirects=True,
            )

            response.raise_for_status()

        except requests.RequestException as exc:
            raise PhishTankConnectorError(
                "Unable to retrieve PhishTank "
                "remote metadata."
            ) from exc

        return {
            "etag": response.headers.get("ETag"),
            "last_modified": response.headers.get(
                "Last-Modified"
            ),
            "content_length": self._parse_content_length(
                response.headers.get("Content-Length")
            ),
        }

    def read_local_records(
        self,
        *,
        limit: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """
        Read raw records from the local compressed JSON dump.

        Args:
            limit:
                Optional maximum number of records.

        Returns:
            List of raw dictionaries.
        """

        if limit is not None and limit < 0:
            raise ValueError(
                "limit must be greater than or equal to zero."
            )

        if not self.dump_path.exists():
            raise PhishTankConnectorError(
                "The local PhishTank dump does not exist."
            )

        try:
            with bz2.open(
                self.dump_path,
                mode="rt",
                encoding="utf-8",
            ) as file:
                payload = json.load(file)

        except (
            OSError,
            EOFError,
            UnicodeDecodeError,
            json.JSONDecodeError,
        ) as exc:
            raise PhishTankConnectorError(
                "Unable to read the local PhishTank "
                "compressed JSON dump."
            ) from exc

        if not isinstance(payload, list):
            raise PhishTankConnectorError(
                "The PhishTank JSON payload must be a list."
            )

        records: List[Dict[str, Any]] = []

        selected_payload = (
            payload
            if limit is None
            else payload[:limit]
        )

        for index, item in enumerate(selected_payload):
            if not isinstance(item, dict):
                raise PhishTankConnectorError(
                    "Invalid PhishTank record at "
                    f"index {index}: expected a dictionary."
                )

            records.append(item)

        return records

    def get_local_state(
        self,
    ) -> Dict[str, Any]:
        """
        Return persisted synchronization metadata.
        """

        return self._load_state()

    # ============================================================
    # Download
    # ============================================================

    def _download_snapshot(
        self,
    ) -> Dict[str, Any]:
        """
        Download the compressed snapshot safely.

        The response is first written to a temporary file.
        The final dump is replaced only after the download
        completes successfully.
        """

        temporary_path = self.dump_path.with_suffix(
            self.dump_path.suffix + ".tmp"
        )

        try:
            with self.session.get(
                self.download_url,
                headers=self._headers(),
                timeout=self.timeout,
                stream=True,
                allow_redirects=True,
            ) as response:
                response.raise_for_status()

                with temporary_path.open("wb") as file:
                    for chunk in response.iter_content(
                        chunk_size=64 * 1024
                    ):
                        if chunk:
                            file.write(chunk)

                response_metadata = {
                    "etag": response.headers.get("ETag"),
                    "last_modified": (
                        response.headers.get(
                            "Last-Modified"
                        )
                    ),
                    "content_length": (
                        self._parse_content_length(
                            response.headers.get(
                                "Content-Length"
                            )
                        )
                    ),
                }

            self._validate_downloaded_file(
                temporary_path
            )

            temporary_path.replace(
                self.dump_path
            )

            return response_metadata

        except requests.RequestException as exc:
            self._remove_file_safely(
                temporary_path
            )

            raise PhishTankConnectorError(
                "Unable to download the PhishTank snapshot."
            ) from exc

        except OSError as exc:
            self._remove_file_safely(
                temporary_path
            )

            raise PhishTankConnectorError(
                "Unable to persist the PhishTank snapshot."
            ) from exc

        except PhishTankConnectorError:
            self._remove_file_safely(
                temporary_path
            )
            raise

    @staticmethod
    def _validate_downloaded_file(
        file_path: Path,
    ) -> None:
        """
        Verify that the downloaded file is a valid BZ2 JSON
        document containing a list.

        The complete content is not retained in memory after
        validation.
        """

        if not file_path.exists():
            raise PhishTankConnectorError(
                "The downloaded PhishTank file is missing."
            )

        if file_path.stat().st_size == 0:
            raise PhishTankConnectorError(
                "The downloaded PhishTank file is empty."
            )

        try:
            with bz2.open(
                file_path,
                mode="rt",
                encoding="utf-8",
            ) as file:
                payload = json.load(file)

        except (
            OSError,
            EOFError,
            UnicodeDecodeError,
            json.JSONDecodeError,
        ) as exc:
            raise PhishTankConnectorError(
                "The downloaded PhishTank file is not "
                "a valid BZ2 JSON snapshot."
            ) from exc

        if not isinstance(payload, list):
            raise PhishTankConnectorError(
                "The downloaded PhishTank JSON payload "
                "must be a list."
            )

    # ============================================================
    # Synchronization state
    # ============================================================

    def _load_state(
        self,
    ) -> Dict[str, Any]:
        if not self.state_path.exists():
            return {}

        try:
            with self.state_path.open(
                "r",
                encoding="utf-8",
            ) as file:
                state = json.load(file)

        except (
            OSError,
            UnicodeDecodeError,
            json.JSONDecodeError,
        ) as exc:
            raise PhishTankConnectorError(
                "Unable to read the PhishTank "
                "synchronization state."
            ) from exc

        if not isinstance(state, dict):
            raise PhishTankConnectorError(
                "The PhishTank synchronization state "
                "must be a JSON object."
            )

        return state

    def _save_state(
        self,
        state: Dict[str, Any],
    ) -> None:
        temporary_path = self.state_path.with_suffix(
            self.state_path.suffix + ".tmp"
        )

        try:
            with temporary_path.open(
                "w",
                encoding="utf-8",
            ) as file:
                json.dump(
                    state,
                    file,
                    ensure_ascii=False,
                    indent=2,
                )

            temporary_path.replace(
                self.state_path
            )

        except OSError as exc:
            self._remove_file_safely(
                temporary_path
            )

            raise PhishTankConnectorError(
                "Unable to persist the PhishTank "
                "synchronization state."
            ) from exc

    # ============================================================
    # Helpers
    # ============================================================

    def _headers(
        self,
    ) -> Dict[str, str]:
        return {
            "User-Agent": self.user_agent,
            "Accept": (
                "application/json, "
                "application/octet-stream"
            ),
        }

    @staticmethod
    def _parse_content_length(
        value: Optional[str],
    ) -> Optional[int]:
        if value is None:
            return None

        try:
            parsed_value = int(value)
        except (TypeError, ValueError):
            return None

        return (
            parsed_value
            if parsed_value >= 0
            else None
        )

    @staticmethod
    def _remove_file_safely(
        file_path: Path,
    ) -> None:
        try:
            file_path.unlink(missing_ok=True)
        except OSError:
            pass