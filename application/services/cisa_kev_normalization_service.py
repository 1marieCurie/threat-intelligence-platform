from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID

from application.ports.outbound.raw_payload_repository import (
    PersistedRawPayload,
    RawPayloadRecoveryResult,
)
from application.ports.outbound.unit_of_work import (
    UnitOfWork,
)
from application.security.sensitive_data_redactor import (
    redact_sensitive_data,
)
from application.services.cisa_kev_normalizer import (
    CisaKevNormalizer,
)


@dataclass(frozen=True, slots=True)
class CisaKevNormalizationResult:
    claimed: int
    normalized: int
    already_normalized: int
    failed: int
    requeued: int
    stale_failed: int


class CisaKevNormalizationService:
    _STALE_FAILURE_MESSAGE = (
        "Processing lease expired "
        "after maximum attempts"
    )

    def __init__(
        self,
        *,
        unit_of_work: UnitOfWork,
        normalizer: CisaKevNormalizer,
        lease_timeout: timedelta = timedelta(
            minutes=15
        ),
        max_attempts: int = 3,
    ) -> None:
        if unit_of_work is None:
            raise ValueError(
                "unit_of_work must not be None"
            )

        if normalizer is None:
            raise ValueError(
                "normalizer must not be None"
            )

        self._validate_lease_timeout(
            lease_timeout
        )
        self._validate_max_attempts(
            max_attempts
        )

        self._unit_of_work = unit_of_work
        self._normalizer = normalizer
        self._lease_timeout = lease_timeout
        self._max_attempts = max_attempts

    def process_pending(
        self,
        *,
        source_id: UUID,
        limit: int = 100,
    ) -> CisaKevNormalizationResult:
        self._validate_source_id(
            source_id
        )
        self._validate_limit(
            limit
        )

        recovery_result = (
            self._recover_stale_processing(
                source_id=source_id
            )
        )

        claimed_payloads = self._claim_pending(
            source_id=source_id,
            limit=limit,
        )

        normalized_count = 0
        already_normalized_count = 0
        failed_count = 0

        for raw_payload in claimed_payloads:
            try:
                was_normalized = self._process_one(
                    raw_payload
                )

            except Exception as error:
                self._mark_failed(
                    payload_id=raw_payload.id,
                    error=error,
                )

                failed_count += 1
                continue

            if was_normalized:
                normalized_count += 1
            else:
                already_normalized_count += 1

        return CisaKevNormalizationResult(
            claimed=len(
                claimed_payloads
            ),
            normalized=normalized_count,
            already_normalized=(
                already_normalized_count
            ),
            failed=failed_count,
            requeued=recovery_result.requeued,
            stale_failed=recovery_result.failed,
        )

    def _recover_stale_processing(
        self,
        *,
        source_id: UUID,
    ) -> RawPayloadRecoveryResult:
        stale_before = (
            datetime.now(UTC)
            - self._lease_timeout
        )

        with self._unit_of_work as unit_of_work:
            result = (
                unit_of_work.raw_payloads
                .recover_stale_processing(
                    source_id=source_id,
                    stale_before=stale_before,
                    max_attempts=(
                        self._max_attempts
                    ),
                    failure_message=(
                        self._STALE_FAILURE_MESSAGE
                    ),
                )
            )

            unit_of_work.commit()

        return result

    def _claim_pending(
        self,
        *,
        source_id: UUID,
        limit: int,
    ) -> tuple[PersistedRawPayload, ...]:
        with self._unit_of_work as unit_of_work:
            claimed = tuple(
                unit_of_work.raw_payloads
                .claim_pending(
                    source_id=source_id,
                    limit=limit,
                )
            )

            unit_of_work.commit()

        return claimed

    def _process_one(
        self,
        raw_payload: PersistedRawPayload,
    ) -> bool:
        with self._unit_of_work as unit_of_work:
            already_exists = (
                unit_of_work
                .cisa_kev_vulnerabilities
                .exists_by_raw_payload_id(
                    raw_payload.id
                )
            )

            if already_exists:
                self._mark_processed_or_fail(
                    unit_of_work=unit_of_work,
                    payload_id=raw_payload.id,
                )

                unit_of_work.commit()
                return False

            vulnerability = (
                self._normalizer.normalize(
                    raw_payload_id=(
                        raw_payload.id
                    ),
                    payload=raw_payload.payload,
                )
            )

            unit_of_work \
                .cisa_kev_vulnerabilities \
                .save(
                    vulnerability
                )

            self._mark_processed_or_fail(
                unit_of_work=unit_of_work,
                payload_id=raw_payload.id,
            )

            unit_of_work.commit()

        return True

    @staticmethod
    def _mark_processed_or_fail(
        *,
        unit_of_work: UnitOfWork,
        payload_id: UUID,
    ) -> None:
        updated = (
            unit_of_work.raw_payloads
            .mark_processed(
                payload_id=payload_id
            )
        )

        if not updated:
            raise RuntimeError(
                "Unable to mark raw payload "
                "as processed"
            )

    def _mark_failed(
        self,
        *,
        payload_id: UUID,
        error: Exception,
    ) -> None:
        error_message = (
            self._build_error_message(
                error
            )
        )

        with self._unit_of_work as unit_of_work:
            updated = (
                unit_of_work.raw_payloads
                .mark_failed(
                    payload_id=payload_id,
                    error_message=error_message,
                )
            )

            if not updated:
                raise RuntimeError(
                    "Unable to mark raw payload "
                    "as failed"
                ) from error

            unit_of_work.commit()

    @staticmethod
    def _build_error_message(
        error: Exception,
    ) -> str:
        error_type = type(error).__name__
        message = str(error).strip()

        raw_message = (
            f"{error_type}: {message}"
            if message
            else error_type
        )

        return redact_sensitive_data(
            raw_message,
            max_length=500,
        )

    @staticmethod
    def _validate_source_id(
        source_id: UUID,
    ) -> None:
        if not isinstance(
            source_id,
            UUID,
        ):
            raise TypeError(
                "source_id must be a UUID"
            )

    @staticmethod
    def _validate_limit(
        limit: int,
    ) -> None:
        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
        ):
            raise TypeError(
                "limit must be an integer"
            )

        if limit < 1:
            raise ValueError(
                "limit must be greater than zero"
            )

    @staticmethod
    def _validate_lease_timeout(
        lease_timeout: timedelta,
    ) -> None:
        if not isinstance(
            lease_timeout,
            timedelta,
        ):
            raise TypeError(
                "lease_timeout must be "
                "a timedelta"
            )

        if lease_timeout.total_seconds() <= 0:
            raise ValueError(
                "lease_timeout must be positive"
            )

    @staticmethod
    def _validate_max_attempts(
        max_attempts: int,
    ) -> None:
        if (
            isinstance(max_attempts, bool)
            or not isinstance(
                max_attempts,
                int,
            )
        ):
            raise TypeError(
                "max_attempts must be an integer"
            )

        if max_attempts < 1:
            raise ValueError(
                "max_attempts must be "
                "greater than zero"
            )