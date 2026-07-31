from __future__ import annotations

import re
from collections.abc import (
    Iterable,
    Mapping,
    Sequence,
)
from datetime import date, datetime
from math import isfinite
from types import TracebackType
from typing import Any, Self

import requests

from application.models.epss_snapshot import (
    EPSSSnapshot,
)
from application.ports.outbound.epss_provider import (
    EPSSProvider,
    EPSSProviderError,
    EPSSProviderUnavailableError,
    InvalidEPSSResponseError,
)


class EPSSConnector(EPSSProvider):
    """
    Adaptateur HTTP pour l'API EPSS de FIRST.

    Le contrat principal retourne des EPSSSnapshot validés.

    Les anciennes méthodes retournant le JSON brut sont
    temporairement conservées pour maintenir la compatibilité
    avec l'ancien service d'enrichissement.
    """

    BASE_URL = (
        "https://api.first.org/data/v1/epss"
    )

    TIMEOUT = 10.0

    MAX_CVE_QUERY_LENGTH = 2000

    CVE_ID_PATTERN = re.compile(
        r"^CVE-[0-9]{4}-[0-9]{4,}$",
        re.IGNORECASE,
    )

    def __init__(
        self,
        *,
        session: requests.Session | None = None,
        timeout: float = TIMEOUT,
    ) -> None:
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
        ):
            raise TypeError(
                "timeout must be a number"
            )

        normalized_timeout = float(timeout)

        if (
            not isfinite(normalized_timeout)
            or normalized_timeout <= 0
        ):
            raise ValueError(
                "timeout must be a finite "
                "positive number"
            )

        self._owns_session = session is None
        self.session = (
            session
            if session is not None
            else requests.Session()
        )

        self._timeout = normalized_timeout

        self.session.headers.update(
            {
                "Accept": "application/json",
                "User-Agent": (
                    "Threat-Intelligence-Engine"
                ),
            }
        )

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()

    def close(self) -> None:
        """
        Ferme uniquement la session créée par le connecteur.

        Une session injectée reste sous la responsabilité
        de son appelant.
        """
        if self._owns_session:
            self.session.close()

    def fetch_by_cve_ids(
        self,
        cve_ids: Iterable[str],
        *,
        score_date: date | None = None,
    ) -> Mapping[str, EPSSSnapshot]:
        """
        Récupère et valide les snapshots EPSS demandés.

        Le batching et le format JSON restent des détails
        internes à l'adaptateur.
        """
        normalized_cve_ids = self._clean_cve_ids(
            cve_ids
        )

        if not normalized_cve_ids:
            return {}

        query_date = self._normalize_score_date(
            score_date
        )

        snapshots: dict[
            str,
            EPSSSnapshot,
        ] = {}

        batches = self._build_cve_batches(
            normalized_cve_ids
        )

        for batch in batches:
            payload = self._fetch_raw_batch(
                cve_ids=batch,
                score_date=query_date,
            )

            batch_snapshots = (
                self._parse_response(
                    payload=payload,
                    expected_cve_ids=set(batch),
                )
            )

            for cve_id, snapshot in (
                batch_snapshots.items()
            ):
                existing_snapshot = snapshots.get(
                    cve_id
                )

                if (
                    existing_snapshot is not None
                    and existing_snapshot != snapshot
                ):
                    raise InvalidEPSSResponseError(
                        "FIRST EPSS returned "
                        "conflicting duplicate data "
                        f"for {cve_id}"
                    )

                snapshots[cve_id] = snapshot

        # Préserve l'ordre des CVE demandés.
        return {
            cve_id: snapshots[cve_id]
            for cve_id in normalized_cve_ids
            if cve_id in snapshots
        }

    def fetch_by_cve(
        self,
        cve_id: str,
        date: str | None = None,
    ) -> dict[str, Any]:
        """
        Ancienne interface retournant le JSON FIRST brut.

        Cette méthode sera supprimée lorsque l'ancien service
        d'enrichissement utilisera PostgreSQL.
        """
        return self.fetch_by_cves(
            cve_ids=[cve_id],
            date=date,
        )

    def fetch_by_cves(
        self,
        cve_ids: Iterable[str],
        date: str | None = None,
    ) -> dict[str, Any]:
        """
        Ancienne interface de récupération brute par lot.
        """
        normalized_cve_ids = self._clean_cve_ids(
            cve_ids
        )

        if not normalized_cve_ids:
            return self._empty_response()

        score_date = self._normalize_date_string(
            date
        )

        return self._fetch_raw_batch(
            cve_ids=normalized_cve_ids,
            score_date=score_date,
        )

    def fetch_by_batches(
        self,
        cve_ids: Iterable[str],
        date: str | None = None,
    ) -> list[dict[str, Any]]:
        """
        Ancienne interface retournant plusieurs réponses brutes.
        """
        normalized_cve_ids = self._clean_cve_ids(
            cve_ids
        )

        if not normalized_cve_ids:
            return []

        score_date = self._normalize_date_string(
            date
        )

        batches = self._build_cve_batches(
            normalized_cve_ids
        )

        return [
            self._fetch_raw_batch(
                cve_ids=batch,
                score_date=score_date,
            )
            for batch in batches
        ]

    def _fetch_raw_batch(
        self,
        *,
        cve_ids: Sequence[str],
        score_date: str | None,
    ) -> dict[str, Any]:
        cve_query = ",".join(cve_ids)

        if (
            len(cve_query)
            > self.MAX_CVE_QUERY_LENGTH
        ):
            raise ValueError(
                "The CVE query parameter exceeds "
                "the FIRST EPSS maximum size of "
                "2000 characters"
            )

        params: dict[str, str | int] = {
            "cve": cve_query,

            # FIRST utilise une limite par défaut de 100.
            # La préciser évite une réponse tronquée lorsque
            # le batch contient plus de 100 CVE.
            "limit": len(cve_ids),
        }

        if score_date is not None:
            params["date"] = score_date

        try:
            response = self.session.get(
                self.BASE_URL,
                params=params,
                timeout=self._timeout,
            )

            response.raise_for_status()

        except requests.Timeout as error:
            raise EPSSProviderUnavailableError(
                "FIRST EPSS request timed out"
            ) from error

        except requests.ConnectionError as error:
            raise EPSSProviderUnavailableError(
                "FIRST EPSS connection failed"
            ) from error

        except requests.HTTPError as error:
            status_code = (
                error.response.status_code
                if error.response is not None
                else None
            )

            if (
                status_code == 429
                or (
                    status_code is not None
                    and status_code >= 500
                )
            ):
                raise (
                    EPSSProviderUnavailableError(
                        "FIRST EPSS is temporarily "
                        f"unavailable: HTTP {status_code}"
                    )
                ) from error

            raise EPSSProviderError(
                "FIRST EPSS request failed: "
                f"HTTP {status_code}"
            ) from error

        except requests.RequestException as error:
            raise EPSSProviderError(
                "FIRST EPSS request failed"
            ) from error

        try:
            payload = response.json()
        except ValueError as error:
            raise InvalidEPSSResponseError(
                "FIRST EPSS returned invalid JSON"
            ) from error

        if not isinstance(payload, dict):
            raise InvalidEPSSResponseError(
                "FIRST EPSS response must "
                "be a JSON object"
            )

        return payload

    def _parse_response(
        self,
        *,
        payload: Mapping[str, Any],
        expected_cve_ids: set[str],
    ) -> dict[str, EPSSSnapshot]:
        self._validate_response_status(
            payload
        )

        raw_records = payload.get("data")

        if not isinstance(raw_records, list):
            raise InvalidEPSSResponseError(
                "FIRST EPSS response field "
                "'data' must be a list"
            )

        api_version = self._extract_api_version(
            payload
        )

        snapshots: dict[
            str,
            EPSSSnapshot,
        ] = {}

        for index, raw_record in enumerate(
            raw_records
        ):
            if not isinstance(
                raw_record,
                Mapping,
            ):
                raise InvalidEPSSResponseError(
                    "FIRST EPSS record at index "
                    f"{index} must be an object"
                )

            cve_id, snapshot = (
                self._parse_record(
                    raw_record=raw_record,
                    api_version=api_version,
                )
            )

            # Empêche une réponse inattendue d'injecter
            # un score associé à un autre CVE.
            if cve_id not in expected_cve_ids:
                raise InvalidEPSSResponseError(
                    "FIRST EPSS returned an "
                    "unexpected CVE identifier: "
                    f"{cve_id}"
                )

            existing_snapshot = snapshots.get(
                cve_id
            )

            if (
                existing_snapshot is not None
                and existing_snapshot != snapshot
            ):
                raise InvalidEPSSResponseError(
                    "FIRST EPSS returned "
                    "conflicting duplicate data "
                    f"for {cve_id}"
                )

            snapshots[cve_id] = snapshot

        return snapshots

    def _parse_record(
        self,
        *,
        raw_record: Mapping[str, Any],
        api_version: str | None,
    ) -> tuple[str, EPSSSnapshot]:
        cve_id = self._normalize_cve_id(
            raw_record.get("cve")
        )

        if cve_id is None:
            raise InvalidEPSSResponseError(
                "FIRST EPSS returned an invalid "
                "CVE identifier"
            )

        score = self._parse_probability(
            raw_record.get("epss"),
            field_name="epss",
            cve_id=cve_id,
        )

        percentile = self._parse_probability(
            raw_record.get("percentile"),
            field_name="percentile",
            cve_id=cve_id,
        )

        raw_score_date = raw_record.get(
            "date"
        )

        if not isinstance(
            raw_score_date,
            str,
        ):
            raise InvalidEPSSResponseError(
                "FIRST EPSS returned an invalid "
                f"date for {cve_id}"
            )

        try:
            parsed_score_date = (
                date.fromisoformat(
                    raw_score_date.strip()
                )
            )
        except ValueError as error:
            raise InvalidEPSSResponseError(
                "FIRST EPSS returned an invalid "
                f"date for {cve_id}"
            ) from error

        try:
            snapshot = EPSSSnapshot(
                score=score,
                percentile=percentile,
                score_date=parsed_score_date,
                api_version=api_version,
            )
        except (
            TypeError,
            ValueError,
        ) as error:
            raise InvalidEPSSResponseError(
                "FIRST EPSS returned invalid "
                f"values for {cve_id}"
            ) from error

        return cve_id, snapshot

    @staticmethod
    def _parse_probability(
        value: object,
        *,
        field_name: str,
        cve_id: str,
    ) -> float:
        if (
            isinstance(value, bool)
            or not isinstance(
                value,
                (str, int, float),
            )
        ):
            raise InvalidEPSSResponseError(
                "FIRST EPSS returned an invalid "
                f"{field_name} value for {cve_id}"
            )

        try:
            return float(value)
        except ValueError as error:
            raise InvalidEPSSResponseError(
                "FIRST EPSS returned an invalid "
                f"{field_name} value for {cve_id}"
            ) from error

    @staticmethod
    def _validate_response_status(
        payload: Mapping[str, Any],
    ) -> None:
        status = payload.get("status")

        if (
            status is not None
            and status != "OK"
        ):
            raise InvalidEPSSResponseError(
                "FIRST EPSS returned a non-OK "
                "response status"
            )

        raw_status_code = payload.get(
            "status-code"
        )

        if raw_status_code is None:
            return

        if isinstance(raw_status_code, bool):
            raise InvalidEPSSResponseError(
                "FIRST EPSS returned an invalid "
                "response status code"
            )

        try:
            status_code = int(
                raw_status_code
            )
        except (
            TypeError,
            ValueError,
        ) as error:
            raise InvalidEPSSResponseError(
                "FIRST EPSS returned an invalid "
                "response status code"
            ) from error

        if status_code != 200:
            raise InvalidEPSSResponseError(
                "FIRST EPSS returned a non-200 "
                "response status code"
            )

    @staticmethod
    def _extract_api_version(
        payload: Mapping[str, Any],
    ) -> str | None:
        raw_version = payload.get(
            "version"
        )

        if raw_version is None:
            return None

        if (
            isinstance(raw_version, bool)
            or not isinstance(
                raw_version,
                (str, int, float),
            )
        ):
            raise InvalidEPSSResponseError(
                "FIRST EPSS returned an invalid "
                "API version"
            )

        normalized_version = str(
            raw_version
        ).strip()

        if not normalized_version:
            raise InvalidEPSSResponseError(
                "FIRST EPSS returned an empty "
                "API version"
            )

        return normalized_version

    @classmethod
    def _clean_cve_ids(
        cls,
        cve_ids: Iterable[object],
    ) -> list[str]:
        """
        Nettoie, valide et déduplique les CVE.

        Les valeurs invalides sont ignorées afin de maintenir
        la compatibilité avec l'ancien connecteur.
        """
        if isinstance(
            cve_ids,
            (str, bytes),
        ):
            raise TypeError(
                "cve_ids must be an iterable "
                "of CVE identifiers"
            )

        try:
            provided_values = list(cve_ids)
        except TypeError as error:
            raise TypeError(
                "cve_ids must be an iterable "
                "of CVE identifiers"
            ) from error

        normalized_cve_ids: list[str] = []
        seen: set[str] = set()

        for value in provided_values:
            normalized_cve_id = (
                cls._normalize_cve_id(
                    value
                )
            )

            if normalized_cve_id is None:
                continue

            if normalized_cve_id in seen:
                continue

            normalized_cve_ids.append(
                normalized_cve_id
            )

            seen.add(
                normalized_cve_id
            )

        return normalized_cve_ids

    @classmethod
    def _normalize_cve_id(
        cls,
        value: object,
    ) -> str | None:
        if not isinstance(value, str):
            return None

        normalized_value = (
            value.strip().upper()
        )

        if (
            len(normalized_value) > 32
            or cls.CVE_ID_PATTERN.fullmatch(
                normalized_value
            )
            is None
        ):
            return None

        return normalized_value

    def _build_cve_batches(
        self,
        cve_ids: Sequence[str],
    ) -> list[list[str]]:
        """
        Construit des lots respectant la limite FIRST
        de 2 000 caractères.
        """
        batches: list[list[str]] = []
        current_batch: list[str] = []
        current_length = 0

        for cve_id in cve_ids:
            if (
                len(cve_id)
                > self.MAX_CVE_QUERY_LENGTH
            ):
                raise ValueError(
                    "A CVE identifier exceeds "
                    "the FIRST query limit"
                )

            additional_length = len(cve_id)

            if current_batch:
                additional_length += 1

            if (
                current_batch
                and (
                    current_length
                    + additional_length
                    > self.MAX_CVE_QUERY_LENGTH
                )
            ):
                batches.append(
                    current_batch
                )

                current_batch = [cve_id]
                current_length = len(cve_id)

            else:
                current_batch.append(cve_id)
                current_length += additional_length

        if current_batch:
            batches.append(
                current_batch
            )

        return batches

    @staticmethod
    def _normalize_score_date(
        value: date | None,
    ) -> str | None:
        if value is None:
            return None

        if (
            not isinstance(value, date)
            or isinstance(value, datetime)
        ):
            raise TypeError(
                "score_date must be a date "
                "or None"
            )

        return value.isoformat()

    @staticmethod
    def _normalize_date_string(
        value: str | None,
    ) -> str | None:
        if value is None:
            return None

        if not isinstance(value, str):
            raise TypeError(
                "date must be a string or None"
            )

        try:
            parsed_date = date.fromisoformat(
                value.strip()
            )
        except ValueError as error:
            raise ValueError(
                "date must use the "
                "YYYY-MM-DD format"
            ) from error

        return parsed_date.isoformat()

    @staticmethod
    def _empty_response() -> dict[str, Any]:
        return {
            "status": "OK",
            "status-code": 200,
            "total": 0,
            "data": [],
        }