from __future__ import annotations

from application.models.canonical_web_indicator_observation import (
    CanonicalWebIndicatorObservation,
)
from application.models.urlhaus_canonical_source_record import (
    URLhausCanonicalSourceRecord,
)
from application.services.canonical_url_normalizer import (
    CanonicalURLNormalizer,
)
from domain.web_indicator_observation import (
    WebIndicatorObservation,
)


class URLhausCanonicalObservationBuilder:
    SOURCE = "urlhaus"

    SUPPORTED_STATUSES = frozenset(
        {
            "online",
            "offline",
        }
    )

    def __init__(
        self,
        *,
        url_normalizer: (
            CanonicalURLNormalizer | None
        ) = None,
    ) -> None:
        self._url_normalizer = (
            url_normalizer
            or CanonicalURLNormalizer()
        )

    def build(
        self,
        *,
        record: URLhausCanonicalSourceRecord,
    ) -> CanonicalWebIndicatorObservation:
        if not isinstance(
            record,
            URLhausCanonicalSourceRecord,
        ):
            raise TypeError(
                "record must be a "
                "URLhausCanonicalSourceRecord"
            )

        identity = self._url_normalizer.normalize(
            record.malicious_url
        )

        observed_at = (
            record.date_added
            or record.normalized_at
        )

        source_status = self._source_status(
            record.url_status
        )

        observation = WebIndicatorObservation(
            source=self.SOURCE,
            source_record_key=str(
                record.urlhaus_id
            ),
            normalized_record_id=(
                record.normalized_record_id
            ),
            observed_at=observed_at,
            last_observed_at=max(
                observed_at,
                record.normalized_at,
            ),
            normalizer_version=(
                record.normalizer_version
            ),
            source_status=source_status,
            is_active=self._is_active(
                source_status
            ),
            labels=(
                "malware_distribution",
            ),
        )

        return CanonicalWebIndicatorObservation(
            identity=identity,
            observation=observation,
        )

    @classmethod
    def _source_status(
        cls,
        value: str | None,
    ) -> str | None:
        if value in cls.SUPPORTED_STATUSES:
            return value

        return None

    @staticmethod
    def _is_active(
        status: str | None,
    ) -> bool | None:
        if status == "online":
            return True

        if status == "offline":
            return False

        return None