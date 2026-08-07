from __future__ import annotations

import csv
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Iterator
from urllib.parse import quote

import requests
from requests import Session


class URLhausDatabaseDumpError(
    RuntimeError
):
    """
    Erreur sûre du téléchargement du dump URLhaus.

    Aucun IOC, Auth-Key ou contenu fournisseur ne doit
    apparaître dans le message.
    """


@dataclass(
    frozen=True,
    slots=True,
)
class URLhausDatabaseDumpRecord:
    external_record_id: str
    payload: dict[str, object]
    retrieved_at: datetime
    source_url: str


class URLhausDatabaseDumpConnector:
    """
    Stream le dump URLhaus actif + 90 jours.

    Garanties :
    - pas de chargement complet en mémoire ;
    - Auth-Key jamais exposée dans les logs ;
    - parsing CSV borné ;
    - aucune URL malveillante journalisée.
    """

    VERSION = "1.0.0"

    BASE_URL = (
        "https://urlhaus-api.abuse.ch"
    )

    SAFE_SOURCE_URL = (
        "https://urlhaus-api.abuse.ch/"
        "v2/files/exports/recent.csv"
    )

    DEFAULT_TIMEOUT = (
        30.0,
        120.0,
    )

    MAX_ROWS = 2_000_000

    def __init__(
        self,
        *,
        auth_key: str,
        session: Session | None = None,
    ) -> None:
        normalized_auth_key = (
            self._validate_auth_key(
                auth_key
            )
        )

        self._auth_key = (
            normalized_auth_key
        )

        self._session = (
            session
            if session is not None
            else requests.Session()
        )

    def iter_records(
        self,
    ) -> Iterator[
        URLhausDatabaseDumpRecord
    ]:
        request_url = self._build_request_url()

        try:
            with self._session.get(
                request_url,
                headers={
                    "Accept": (
                        "text/csv,"
                        "application/octet-stream"
                    ),
                    "User-Agent": (
                        "threat-intelligence-engine/0.1"
                    ),
                },
                timeout=self.DEFAULT_TIMEOUT,
                stream=True,
            ) as response:
                if response.status_code in {
                    401,
                    403,
                }:
                    raise (
                        URLhausDatabaseDumpError(
                            "URLhaus dump "
                            "authentication failed"
                        )
                    )

                try:
                    response.raise_for_status()

                except requests.HTTPError:
                    raise (
                        URLhausDatabaseDumpError(
                            "URLhaus dump returned "
                            "an HTTP error"
                        )
                    ) from None

                response.encoding = "utf-8"

                retrieved_at = (
                    datetime.now(UTC)
                )

                yield from self._iter_csv_records(
                    response=response,
                    retrieved_at=(
                        retrieved_at
                    ),
                )

        except URLhausDatabaseDumpError:
            raise

        except (
            requests.Timeout,
            requests.RequestException,
        ):
            raise URLhausDatabaseDumpError(
                "URLhaus dump download failed"
            ) from None

    def _iter_csv_records(
        self,
        *,
        response: requests.Response,
        retrieved_at: datetime,
    ) -> Iterator[
        URLhausDatabaseDumpRecord
    ]:
        lines: Iterator[str] = (
            line.decode("utf-8")
            if isinstance(line, bytes)
            else line
            for line
            in response.iter_lines(
                decode_unicode=True
            )
            if line is not None
        )

        reader = csv.reader(
            lines
        )

        records_seen = 0

        try:
            for row_number, row in enumerate(
                reader,
                start=1,
            ):
                if not row:
                    continue

                first_value = (
                    row[0].strip()
                )

                if (
                    not first_value
                    or first_value.startswith("#")
                ):
                    continue

                if (
                    first_value.lower() == "id"
                    and len(row) > 1
                    and row[1]
                    .strip()
                    .lower()
                    in {
                        "dateadded",
                        "date_added",
                    }
                ):
                    continue

                records_seen += 1

                if (
                    records_seen
                    > self.MAX_ROWS
                ):
                    raise (
                        URLhausDatabaseDumpError(
                            "URLhaus dump exceeds "
                            "configured row limit"
                        )
                    )

                payload = (
                    self._row_to_payload(
                        row=row,
                        row_number=row_number,
                    )
                )

                yield (
                    URLhausDatabaseDumpRecord(
                        external_record_id=(
                            str(
                                payload["id"]
                            )
                        ),
                        payload=payload,
                        retrieved_at=(
                            retrieved_at
                        ),
                        source_url=(
                            self.SAFE_SOURCE_URL
                        ),
                    )
                )

        except csv.Error:
            raise URLhausDatabaseDumpError(
                "URLhaus dump CSV is invalid"
            ) from None

    @classmethod
    def _row_to_payload(
        cls,
        *,
        row: list[str],
        row_number: int,
    ) -> dict[str, object]:
        # Format actuel :
        #
        # id,dateadded,url,url_status,
        # last_online,threat,tags,
        # urlhaus_link,reporter
        #
        # L'ancien export pouvait contenir
        # huit colonnes sans last_online.

        if len(row) == 9:
            (
                urlhaus_id,
                date_added,
                url,
                url_status,
                last_online,
                threat,
                tags,
                urlhaus_link,
                reporter,
            ) = row

        elif len(row) == 8:
            (
                urlhaus_id,
                date_added,
                url,
                url_status,
                threat,
                tags,
                urlhaus_link,
                reporter,
            ) = row

            last_online = ""

        else:
            raise URLhausDatabaseDumpError(
                "URLhaus dump row "
                f"{row_number} has an "
                "unsupported column count"
            )

        normalized_id = (
            urlhaus_id.strip()
        )

        if (
            not normalized_id
            or not normalized_id.isascii()
            or not normalized_id.isdigit()
            or int(normalized_id) <= 0
        ):
            raise URLhausDatabaseDumpError(
                "URLhaus dump contains "
                "an invalid record identifier"
            )

        normalized_tags = [
            tag.strip()
            for tag
            in tags.split(",")
            if tag.strip()
        ]

        payload: dict[str, object] = {
            "id": normalized_id,
            "date_added": (
                cls._utc_timestamp(
                    date_added
                )
            ),
            "url": url.strip(),
            "url_status": (
                url_status.strip()
            ),
            "threat": threat.strip(),
            "tags": normalized_tags,
            "urlhaus_reference": (
                urlhaus_link.strip()
            ),
            "reporter": (
                reporter.strip()
            ),
        }

        if last_online.strip():
            payload["last_online"] = (
                cls._utc_timestamp(
                    last_online
                )
            )

        return payload

    @staticmethod
    def _utc_timestamp(
        value: str,
    ) -> str:
        normalized = value.strip()

        if not normalized:
            return ""

        # Le CSV URLhaus utilise historiquement
        # YYYY-MM-DD HH:MM:SS sans suffixe.
        #
        # Le normalizer interne exige une timezone.

        try:
            datetime.strptime(
                normalized,
                "%Y-%m-%d %H:%M:%S",
            )

        except ValueError:
            return normalized

        return (
            f"{normalized} UTC"
        )

    def _build_request_url(
        self,
    ) -> str:
        encoded_key = quote(
            self._auth_key,
            safe="",
        )

        return (
            f"{self.BASE_URL}/"
            "v2/files/exports/"
            f"{encoded_key}/recent.csv"
        )

    @staticmethod
    def _validate_auth_key(
        value: str,
    ) -> str:
        if not isinstance(
            value,
            str,
        ):
            raise TypeError(
                "auth_key must be a string"
            )

        normalized = value.strip()

        if not normalized:
            raise ValueError(
                "auth_key must not be empty"
            )

        if any(
            character.isspace()
            or ord(character) < 32
            or ord(character) == 127
            for character in normalized
        ):
            raise ValueError(
                "auth_key contains "
                "invalid characters"
            )

        return normalized