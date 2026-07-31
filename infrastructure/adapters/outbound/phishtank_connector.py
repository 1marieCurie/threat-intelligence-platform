from __future__ import annotations

import bz2
import json
from datetime import UTC, datetime
from math import isfinite
from pathlib import Path
from typing import Any

import requests


class PhishTankConnectorError(RuntimeError):
    """
    Erreur levée lorsque le connecteur PhishTank ne peut pas
    récupérer, valider, persister ou lire le snapshot.
    """


class PhishTankConnector:
    """
    Adaptateur sortant responsable du snapshot PhishTank.

    La clé applicative n'est utilisée que pour construire l'URL
    HTTP réelle. Elle ne doit jamais être persistée ni exposée
    dans les logs, les métadonnées ou les exceptions publiques.
    """

    PUBLIC_DOWNLOAD_URL = (
        "https://data.phishtank.com/data/"
        "online-valid.json.bz2"
    )

    DEFAULT_DUMP_FILENAME = "online-valid.json.bz2"

    DEFAULT_STATE_FILENAME = (
        "phishtank_sync_state.json"
    )

    _SENSITIVE_STATE_KEYS = frozenset(
        {
            "app_key",
            "api_key",
            "token",
            "authorization",
            "password",
            "secret",
        }
    )

    _URL_STATE_KEYS = frozenset(
        {
            "download_url",
            "source_url",
            "request_url",
        }
    )

    def __init__(
        self,
        storage_directory: str | Path = (
            "data/phishtank"
        ),
        app_key: str | None = None,
        user_agent: str = (
            "threat-intelligence-engine/1.0"
        ),
        timeout: float = 30.0,
        session: requests.Session | None = None,
    ) -> None:
        self.timeout = self._validate_timeout(
            timeout
        )

        self.user_agent = (
            self._validate_user_agent(
                user_agent
            )
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

        self._app_key = (
            normalized_app_key
            or None
        )

        self.session = (
            session
            if session is not None
            else requests.Session()
        )

        self.storage_directory.mkdir(
            parents=True,
            exist_ok=True,
        )

    def __repr__(
        self,
    ) -> str:
        """
        Retourne une représentation sans secret.
        """
        return (
            f"{type(self).__name__}("
            f"storage_directory="
            f"{str(self.storage_directory)!r}, "
            f"app_key_configured="
            f"{self._app_key is not None}, "
            f"timeout={self.timeout!r}"
            ")"
        )

    # ========================================================
    # Configuration publique
    # ========================================================

    @property
    def app_key(
        self,
    ) -> str | None:
        """
        Propriété conservée pour compatibilité.

        Sa valeur ne doit jamais être journalisée ou persistée.
        """
        return self._app_key

    @property
    def download_url(
        self,
    ) -> str:
        """
        Retourne l'URL HTTP réellement utilisée.

        Cette URL peut contenir la clé PhishTank.
        """
        if self._app_key is None:
            return self.PUBLIC_DOWNLOAD_URL

        return (
            "https://data.phishtank.com/data/"
            f"{self._app_key}/"
            "online-valid.json.bz2"
        )

    @property
    def canonical_source_url(
        self,
    ) -> str:
        """
        Retourne l'URL publique utilisable pour la traçabilité.
        """
        return self.PUBLIC_DOWNLOAD_URL

    # ========================================================
    # API publique
    # ========================================================

    def fetch_raw(
        self,
        *,
        force_download: bool = False,
        limit: int | None = None,
    ) -> list[dict[str, Any]]:
        """
        Garantit la présence d'un snapshot local puis retourne
        ses enregistrements bruts.
        """
        self.download_if_updated(
            force=force_download,
        )

        return self.read_local_records(
            limit=limit,
        )

    def download_if_updated(
        self,
        *,
        force: bool = False,
    ) -> dict[str, Any]:
        """
        Télécharge le snapshot uniquement lorsqu'une
        actualisation est nécessaire.

        L'état retourné ne contient jamais la clé PhishTank.
        """
        local_state = self._load_state()

        try:
            remote_metadata = (
                self.get_remote_metadata()
            )

        except PhishTankConnectorError:
            if (
                self.dump_path.exists()
                and not force
            ):
                return self._sanitize_state(
                    {
                        **local_state,
                        "source": "PHISHTANK",
                        "source_url": (
                            self.canonical_source_url
                        ),
                        "download_url": (
                            self.canonical_source_url
                        ),
                        "downloaded": False,
                        "used_local_snapshot": True,
                        "head_request_failed": True,
                        "dump_path": str(
                            self.dump_path
                        ),
                    }
                )

            remote_metadata: dict[
                str,
                Any,
            ] = {}

        remote_etag = (
            remote_metadata.get(
                "etag"
            )
        )

        local_etag = (
            local_state.get(
                "etag"
            )
        )

        dump_exists = (
            self.dump_path.exists()
        )

        should_download = (
            force
            or not dump_exists
            or not local_state
            or (
                remote_etag is not None
                and remote_etag
                != local_etag
            )
        )

        if not should_download:
            return self._sanitize_state(
                {
                    **local_state,
                    **remote_metadata,
                    "source": "PHISHTANK",
                    "source_url": (
                        self.canonical_source_url
                    ),
                    "download_url": (
                        self.canonical_source_url
                    ),
                    "downloaded": False,
                    "used_local_snapshot": True,
                    "head_request_failed": False,
                    "dump_path": str(
                        self.dump_path
                    ),
                }
            )

        download_metadata = (
            self._download_snapshot()
        )

        state = self._sanitize_state(
            {
                "source": "PHISHTANK",
                "source_url": (
                    self.canonical_source_url
                ),
                "download_url": (
                    self.canonical_source_url
                ),
                "etag": (
                    download_metadata.get(
                        "etag"
                    )
                    or remote_etag
                ),
                "last_modified": (
                    download_metadata.get(
                        "last_modified"
                    )
                    or remote_metadata.get(
                        "last_modified"
                    )
                ),
                "content_length": (
                    download_metadata.get(
                        "content_length"
                    )
                    or remote_metadata.get(
                        "content_length"
                    )
                ),
                "downloaded_at": (
                    datetime.now(
                        UTC
                    ).isoformat()
                ),
                "dump_path": str(
                    self.dump_path
                ),
                "downloaded": True,
                "used_local_snapshot": False,
                "head_request_failed": False,
            }
        )

        self._save_state(
            state
        )

        return state

    def get_remote_metadata(
        self,
    ) -> dict[str, Any]:
        """
        Effectue la requête HEAD sans conserver une exception
        requests susceptible d'inclure l'URL authentifiée.
        """
        try:
            response = self.session.head(
                self.download_url,
                headers=self._headers(),
                timeout=self.timeout,
                allow_redirects=True,
            )

            response.raise_for_status()

        except requests.RequestException:
            # La levée publique est effectuée après le bloc
            # except. __cause__ et __context__ restent à None.
            pass

        else:
            return {
                "etag": response.headers.get(
                    "ETag"
                ),
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

        raise PhishTankConnectorError(
            "Unable to retrieve PhishTank "
            "remote metadata."
        )

    def read_local_records(
        self,
        *,
        limit: int | None = None,
    ) -> list[dict[str, Any]]:
        """
        Lit les enregistrements bruts depuis le snapshot BZ2.
        """
        self._validate_limit(
            limit
        )

        if not self.dump_path.exists():
            raise PhishTankConnectorError(
                "The local PhishTank dump "
                "does not exist."
            )

        try:
            with bz2.open(
                self.dump_path,
                mode="rt",
                encoding="utf-8",
            ) as file:
                payload = json.load(
                    file
                )

        except (
            OSError,
            EOFError,
            UnicodeDecodeError,
            json.JSONDecodeError,
        ) as error:
            raise PhishTankConnectorError(
                "Unable to read the local "
                "PhishTank compressed JSON dump."
            ) from error

        if not isinstance(
            payload,
            list,
        ):
            raise PhishTankConnectorError(
                "The PhishTank JSON payload "
                "must be a list."
            )

        selected_payload = (
            payload
            if limit is None
            else payload[:limit]
        )

        records: list[
            dict[str, Any]
        ] = []

        for index, item in enumerate(
            selected_payload
        ):
            if not isinstance(
                item,
                dict,
            ):
                raise PhishTankConnectorError(
                    "Invalid PhishTank record "
                    f"at index {index}: expected "
                    "a dictionary."
                )

            records.append(
                dict(item)
            )

        return records

    def get_local_state(
        self,
    ) -> dict[str, Any]:
        """
        Retourne l'état local après assainissement.
        """
        return self._load_state()

    # ========================================================
    # Téléchargement
    # ========================================================

    def _download_snapshot(
        self,
    ) -> dict[str, Any]:
        """
        Télécharge le snapshot dans un fichier temporaire.

        Les erreurs réseau sont converties sans conserver
        l'exception requests ni l'URL authentifiée.
        """
        temporary_path = (
            self.dump_path.with_suffix(
                self.dump_path.suffix
                + ".tmp"
            )
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

                with temporary_path.open(
                    "wb"
                ) as file:
                    for chunk in response.iter_content(
                        chunk_size=64 * 1024
                    ):
                        if chunk:
                            file.write(
                                chunk
                            )

                response_metadata = {
                    "etag": (
                        response.headers.get(
                            "ETag"
                        )
                    ),
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

        except requests.RequestException:
            self._remove_file_safely(
                temporary_path
            )

            # La levée publique est effectuée hors du bloc
            # except afin de ne conserver aucun contexte.

        except OSError as error:
            self._remove_file_safely(
                temporary_path
            )

            raise PhishTankConnectorError(
                "Unable to persist the "
                "PhishTank snapshot."
            ) from error

        except PhishTankConnectorError:
            self._remove_file_safely(
                temporary_path
            )
            raise

        raise PhishTankConnectorError(
            "Unable to download the "
            "PhishTank snapshot."
        )

    @staticmethod
    def _validate_downloaded_file(
        file_path: Path,
    ) -> None:
        """
        Vérifie que le fichier téléchargé est un document BZ2
        JSON contenant une liste.
        """
        if not file_path.exists():
            raise PhishTankConnectorError(
                "The downloaded PhishTank "
                "file is missing."
            )

        if file_path.stat().st_size == 0:
            raise PhishTankConnectorError(
                "The downloaded PhishTank "
                "file is empty."
            )

        try:
            with bz2.open(
                file_path,
                mode="rt",
                encoding="utf-8",
            ) as file:
                payload = json.load(
                    file
                )

        except (
            OSError,
            EOFError,
            UnicodeDecodeError,
            json.JSONDecodeError,
        ) as error:
            raise PhishTankConnectorError(
                "The downloaded PhishTank file "
                "is not a valid BZ2 JSON snapshot."
            ) from error

        if not isinstance(
            payload,
            list,
        ):
            raise PhishTankConnectorError(
                "The downloaded PhishTank JSON "
                "payload must be a list."
            )

    # ========================================================
    # État local
    # ========================================================

    def _load_state(
        self,
    ) -> dict[str, Any]:
        if not self.state_path.exists():
            return {}

        try:
            with self.state_path.open(
                "r",
                encoding="utf-8",
            ) as file:
                state = json.load(
                    file
                )

        except (
            OSError,
            UnicodeDecodeError,
            json.JSONDecodeError,
        ) as error:
            raise PhishTankConnectorError(
                "Unable to read the PhishTank "
                "synchronization state."
            ) from error

        if not isinstance(
            state,
            dict,
        ):
            raise PhishTankConnectorError(
                "The PhishTank synchronization "
                "state must be a JSON object."
            )

        return self._sanitize_state(
            state
        )

    def _save_state(
        self,
        state: dict[str, Any],
    ) -> None:
        if not isinstance(
            state,
            dict,
        ):
            raise TypeError(
                "state must be a dictionary"
            )

        sanitized_state = (
            self._sanitize_state(
                state
            )
        )

        temporary_path = (
            self.state_path.with_suffix(
                self.state_path.suffix
                + ".tmp"
            )
        )

        try:
            with temporary_path.open(
                "w",
                encoding="utf-8",
            ) as file:
                json.dump(
                    sanitized_state,
                    file,
                    ensure_ascii=False,
                    indent=2,
                )

            temporary_path.replace(
                self.state_path
            )

        except OSError as error:
            self._remove_file_safely(
                temporary_path
            )

            raise PhishTankConnectorError(
                "Unable to persist the "
                "PhishTank synchronization state."
            ) from error

    def _sanitize_state(
        self,
        state: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Retire les secrets, assainit les valeurs imbriquées et
        canonicalise les URL destinées à la persistance.
        """
        return self._sanitize_mapping(
            state
        )

    def _sanitize_mapping(
        self,
        value: dict[str, Any],
    ) -> dict[str, Any]:
        sanitized: dict[
            str,
            Any,
        ] = {}

        for key, item in value.items():
            output_key = (
                key
                if isinstance(key, str)
                else str(key)
            )

            normalized_key = (
                output_key
                .strip()
                .lower()
            )

            if self._is_sensitive_state_key(
                normalized_key
            ):
                continue

            if (
                normalized_key
                in self._URL_STATE_KEYS
            ):
                sanitized[
                    output_key
                ] = self.canonical_source_url

                continue

            sanitized[
                output_key
            ] = self._sanitize_state_value(
                item
            )

        return sanitized

    def _sanitize_state_value(
        self,
        value: Any,
    ) -> Any:
        if isinstance(
            value,
            dict,
        ):
            return self._sanitize_mapping(
                value
            )

        if isinstance(
            value,
            list,
        ):
            return [
                self._sanitize_state_value(
                    item
                )
                for item in value
            ]

        if isinstance(
            value,
            tuple,
        ):
            return [
                self._sanitize_state_value(
                    item
                )
                for item in value
            ]

        if (
            isinstance(value, str)
            and self._app_key
        ):
            return value.replace(
                self._app_key,
                "[REDACTED]",
            )

        return value

    @classmethod
    def _is_sensitive_state_key(
        cls,
        key: str,
    ) -> bool:
        if key in cls._SENSITIVE_STATE_KEYS:
            return True

        return key.endswith(
            (
                "_app_key",
                "_api_key",
                "_token",
                "_password",
                "_secret",
            )
        )

    # ========================================================
    # Validation et helpers
    # ========================================================

    def _headers(
        self,
    ) -> dict[str, str]:
        return {
            "User-Agent": self.user_agent,
            "Accept": (
                "application/json, "
                "application/octet-stream"
            ),
        }

    @staticmethod
    def _parse_content_length(
        value: str | None,
    ) -> int | None:
        if value is None:
            return None

        try:
            parsed_value = int(
                value
            )

        except (
            TypeError,
            ValueError,
        ):
            return None

        return (
            parsed_value
            if parsed_value >= 0
            else None
        )

    @staticmethod
    def _validate_timeout(
        value: float,
    ) -> float:
        if (
            isinstance(value, bool)
            or not isinstance(
                value,
                (int, float),
            )
        ):
            raise TypeError(
                "timeout must be a number."
            )

        normalized = float(
            value
        )

        if (
            not isfinite(normalized)
            or normalized <= 0
        ):
            raise ValueError(
                "timeout must be greater "
                "than zero."
            )

        return normalized

    @staticmethod
    def _validate_user_agent(
        value: str,
    ) -> str:
        if not isinstance(
            value,
            str,
        ):
            raise TypeError(
                "user_agent must be a string."
            )

        normalized = (
            value.strip()
        )

        if not normalized:
            raise ValueError(
                "user_agent must not be empty."
            )

        return normalized

    @staticmethod
    def _validate_limit(
        value: int | None,
    ) -> None:
        if value is None:
            return

        if (
            isinstance(value, bool)
            or not isinstance(
                value,
                int,
            )
        ):
            raise TypeError(
                "limit must be an integer "
                "or None."
            )

        if value < 0:
            raise ValueError(
                "limit must be greater than "
                "or equal to zero."
            )

    @staticmethod
    def _remove_file_safely(
        file_path: Path,
    ) -> None:
        try:
            file_path.unlink(
                missing_ok=True
            )

        except OSError:
            pass