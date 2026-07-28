from __future__ import annotations

from typing import Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


class CISAConnector:
    """
    Connecteur HTTP vers le catalogue CISA KEV.

    Responsabilités :
    - configurer une session HTTP réutilisable ;
    - appliquer un timeout explicite ;
    - réessayer uniquement les requêtes GET idempotentes ;
    - valider le format JSON racine.

    La validation détaillée du catalogue appartient à
    CisaKevIngestionConnector.
    """

    KEV_URL = (
        "https://www.cisa.gov/sites/default/files/feeds/"
        "known_exploited_vulnerabilities.json"
    )

    DEFAULT_TIMEOUT = 30.0

    def __init__(
        self,
        *,
        session: requests.Session | None = None,
        timeout: int | float = DEFAULT_TIMEOUT,
    ) -> None:
        if isinstance(timeout, bool):
            raise TypeError(
                "timeout must be an integer or float."
            )

        if not isinstance(timeout, (int, float)):
            raise TypeError(
                "timeout must be an integer or float."
            )

        if timeout <= 0:
            raise ValueError(
                "timeout must be greater than zero."
            )

        self._timeout = float(timeout)
        self._session = (
            session
            if session is not None
            else self._build_session()
        )

        self._session.headers.update(
            {
                "Accept": "application/json",
                "User-Agent": (
                    "Threat-Intelligence-Engine/1.0"
                ),
            }
        )

    def fetch(self) -> dict[str, Any]:
        """
        Récupère le snapshot complet CISA KEV.
        """

        response = self._session.get(
            self.KEV_URL,
            timeout=self._timeout,
        )

        response.raise_for_status()

        try:
            payload = response.json()
        except ValueError as error:
            raise ValueError(
                "Invalid CISA KEV response: invalid JSON."
            ) from error

        if not isinstance(payload, dict):
            raise ValueError(
                "Invalid CISA KEV response: "
                "expected a JSON object."
            )

        return payload

    @staticmethod
    def _build_session() -> requests.Session:
        """
        Construit une session avec retries bornés.

        Seules les opérations GET sont rejouées.
        """

        retry_policy = Retry(
            total=3,
            connect=3,
            read=3,
            status=3,
            backoff_factor=0.5,
            status_forcelist=(
                429,
                500,
                502,
                503,
                504,
            ),
            allowed_methods=frozenset(
                {
                    "GET",
                }
            ),
            raise_on_status=False,
        )

        adapter = HTTPAdapter(
            max_retries=retry_policy,  # type: ignore[arg-type]
        )

        session = requests.Session()

        session.mount(
            "https://",
            adapter,
        )

        session.mount(
            "http://",
            adapter,
        )

        return session