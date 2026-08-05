from __future__ import annotations

from application.models.canonical_web_indicator_observation import (
    CanonicalWebIndicatorObservation,
)
from application.models.phishtank_canonical_source_record import (
    PhishTankCanonicalSourceRecord,
)
from application.services.canonical_url_normalizer import (
    CanonicalURLNormalizer,
)
from domain.web_indicator_observation import (
    WebIndicatorObservation,
)


class PhishTankCanonicalObservationBuilder:
    SOURCE = "phishtank"

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
        record: PhishTankCanonicalSourceRecord,
    ) -> CanonicalWebIndicatorObservation:
        if not isinstance(
            record,
            PhishTankCanonicalSourceRecord,
        ):
            raise TypeError(
                "record must be a "
                "PhishTankCanonicalSourceRecord"
            )

        identity = self._url_normalizer.normalize(
            record.phishing_url
        )

        observed_at = (
            record.submission_time
            or record.verification_time
            or record.normalized_at
        )

        last_observed_candidates = [
            observed_at,
            record.normalized_at,
        ]

        if record.verification_time is not None:
            last_observed_candidates.append(
                record.verification_time
            )

        observation = WebIndicatorObservation(
            source=self.SOURCE,
            source_record_key=str(
                record.phish_id
            ),
            normalized_record_id=(
                record.normalized_record_id
            ),
            observed_at=observed_at,
            last_observed_at=max(
                last_observed_candidates
            ),
            normalizer_version=(
                record.normalizer_version
            ),
            source_status=(
                self._source_status(
                    record.verified
                )
            ),
            is_active=record.online,
            labels=self._labels(
                record.verified
            ),
        )

        return CanonicalWebIndicatorObservation(
            identity=identity,
            observation=observation,
        )

    @staticmethod
    def _source_status(
        verified: bool | None,
    ) -> str | None:
        if verified is True:
            return "verified"

        if verified is False:
            return "unverified"

        return None

    @staticmethod
    def _labels(
        verified: bool | None,
    ) -> tuple[str, ...]:
        if verified is True:
            return (
                "phishing",
            )

        return (
            "suspected_phishing",
        )