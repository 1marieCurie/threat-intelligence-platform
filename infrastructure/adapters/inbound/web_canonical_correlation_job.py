from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import (
    Generic,
    Protocol,
    TypeVar,
)

from application.services.canonical_web_indicator_correlation_service import (
    CanonicalWebCorrelationResult,
)


_CursorT = TypeVar(
    "_CursorT"
)

_CursorT_co = TypeVar(
    "_CursorT_co",
    covariant=True,
)


_URL_PATTERN = re.compile(
    r"\b[a-z][a-z0-9+.-]*://[^\s]+",
    flags=re.IGNORECASE,
)

_SECRET_ASSIGNMENT_PATTERN = re.compile(
    r"\b("
    r"password|passwd|pwd|token|"
    r"api[_-]?key|secret|authorization"
    r")\b"
    r"\s*[:=]\s*"
    r"(?:bearer\s+)?"
    r"[^\s,;]+",
    flags=re.IGNORECASE,
)

_BEARER_TOKEN_PATTERN = re.compile(
    r"\bbearer\s+[a-z0-9._~+/=-]+",
    flags=re.IGNORECASE,
)

_CONTROL_CHARACTER_PATTERN = re.compile(
    r"[\x00-\x1f\x7f]+"
)


class WebCanonicalBatchResult(
    Protocol[
        _CursorT_co
    ]
):
    """
    Contrat minimal du résultat d'un lot canonique Web.

    Le type du curseur est covariant, car il est uniquement
    exposé en sortie par ce protocole.
    """

    @property
    def records_read(
        self,
    ) -> int:
        ...

    @property
    def next_cursor(
        self,
    ) -> _CursorT_co | None:
        ...

    @property
    def source_exhausted(
        self,
    ) -> bool:
        ...

    @property
    def correlation(
        self,
    ) -> CanonicalWebCorrelationResult:
        ...


class WebCanonicalBatchProcessor(
    Protocol[
        _CursorT
    ]
):
    """
    Processeur d'un seul lot canonique Web.

    Le curseur reste invariant ici, car il est utilisé à la
    fois comme paramètre d'entrée et comme valeur de sortie.
    """

    def process_batch(
        self,
        *,
        after_cursor: (
            _CursorT
            | None
        ) = None,
        limit: int,
    ) -> WebCanonicalBatchResult[
        _CursorT
    ]:
        ...


@dataclass(
    frozen=True,
    slots=True,
)
class WebCanonicalCorrelationJobResult(
    Generic[
        _CursorT
    ]
):
    batches_processed: int
    records_read: int

    source_exhausted: bool
    max_batches_reached: bool

    next_cursor: (
        _CursorT
        | None
    )

    observations_received: int
    components_built: int

    canonical_created: int
    canonical_updated: int
    canonical_persisted: int


@dataclass(
    slots=True,
)
class _WebCanonicalJobCounters:
    batches_processed: int = 0
    records_read: int = 0

    observations_received: int = 0
    components_built: int = 0

    canonical_created: int = 0
    canonical_updated: int = 0
    canonical_persisted: int = 0

    def add(
        self,
        result: WebCanonicalBatchResult[
            object
        ],
    ) -> None:
        self.batches_processed += 1

        self.records_read += (
            result.records_read
        )

        correlation = (
            result.correlation
        )

        self.observations_received += (
            correlation
            .observations_received
        )

        self.components_built += (
            correlation.components_built
        )

        self.canonical_created += (
            correlation.created
        )

        self.canonical_updated += (
            correlation.updated
        )

        self.canonical_persisted += (
            correlation.persisted
        )


class WebCanonicalCorrelationJob(
    Generic[
        _CursorT
    ]
):
    """
    Enchaîne des lots canoniques Web bornés.

    Garanties :

    - aucune session SQLAlchemy conservée ;
    - aucune accumulation des résultats individuels ;
    - limite maximale de lots ;
    - détection d'un lot vide non terminé ;
    - détection d'un curseur immobile ;
    - aucune URL ou donnée sensible journalisée en clair.

    La persistance durable du curseur reste hors de cette
    classe et doit intervenir uniquement après un retour réussi.
    """

    DEFAULT_BATCH_SIZE = 500
    MAX_BATCH_SIZE = 1_000

    DEFAULT_MAX_BATCHES = 10_000

    MAX_LOG_SUMMARY_LENGTH = 1_000

    def __init__(
        self,
        *,
        processor: (
            WebCanonicalBatchProcessor[
                _CursorT
            ]
        ),
        batch_size: int = DEFAULT_BATCH_SIZE,
        max_batches: int = DEFAULT_MAX_BATCHES,
        logger: logging.Logger | None = None,
    ) -> None:
        if processor is None:
            raise ValueError(
                "processor must not be None"
            )

        self._processor = processor

        self._batch_size = (
            self._validate_batch_size(
                batch_size
            )
        )

        self._max_batches = (
            self._validate_max_batches(
                max_batches
            )
        )

        self._logger = (
            logging.getLogger(
                __name__
            )
            if logger is None
            else logger
        )

    def run(
        self,
        *,
        after_cursor: (
            _CursorT
            | None
        ) = None,
    ) -> (
        WebCanonicalCorrelationJobResult[
            _CursorT
        ]
    ):
        counters = (
            _WebCanonicalJobCounters()
        )

        current_cursor = after_cursor

        try:
            for _ in range(
                self._max_batches
            ):
                batch_result = (
                    self._processor
                    .process_batch(
                        after_cursor=(
                            current_cursor
                        ),
                        limit=self._batch_size,
                    )
                )

                self._validate_batch_result(
                    batch_result
                )

                counters.add(
                    batch_result
                )

                records_read = (
                    batch_result.records_read
                )

                next_cursor = (
                    batch_result.next_cursor
                )

                if records_read == 0:
                    if not (
                        batch_result
                        .source_exhausted
                    ):
                        raise RuntimeError(
                            "Web canonical processor "
                            "returned an empty "
                            "non-exhausted batch"
                        )

                    # Un lot vide ne doit pas effacer un
                    # curseur de progression déjà connu.
                    return self._build_result(
                        counters=counters,
                        next_cursor=current_cursor,
                        source_exhausted=True,
                        max_batches_reached=False,
                    )

                if next_cursor is None:
                    raise RuntimeError(
                        "Web canonical pagination "
                        "did not return a next cursor"
                    )

                if next_cursor == current_cursor:
                    raise RuntimeError(
                        "Web canonical pagination "
                        "cursor did not progress"
                    )

                current_cursor = next_cursor

                if (
                    batch_result
                    .source_exhausted
                ):
                    return self._build_result(
                        counters=counters,
                        next_cursor=current_cursor,
                        source_exhausted=True,
                        max_batches_reached=False,
                    )

            return self._build_result(
                counters=counters,
                next_cursor=current_cursor,
                source_exhausted=False,
                max_batches_reached=True,
            )

        except Exception as error:
            self._logger.error(
                "Web canonical correlation "
                "job failed: %s",
                self._sanitize_error_summary(
                    error
                ),
            )

            raise

    def _validate_batch_result(
        self,
        result: WebCanonicalBatchResult[
            _CursorT
        ],
    ) -> None:
        records_read = (
            result.records_read
        )

        if (
            isinstance(
                records_read,
                bool,
            )
            or not isinstance(
                records_read,
                int,
            )
            or records_read < 0
        ):
            raise RuntimeError(
                "Web canonical processor returned "
                "an invalid records_read value"
            )

        if (
            records_read
            > self._batch_size
        ):
            raise RuntimeError(
                "Web canonical processor returned "
                "more records than requested"
            )

        if not isinstance(
            result.source_exhausted,
            bool,
        ):
            raise RuntimeError(
                "Web canonical processor returned "
                "an invalid source_exhausted value"
            )

        correlation = (
            result.correlation
        )

        correlation_counters = (
            correlation
            .observations_received,
            correlation.components_built,
            correlation.created,
            correlation.updated,
            correlation.persisted,
        )

        if any(
            isinstance(
                value,
                bool,
            )
            or not isinstance(
                value,
                int,
            )
            or value < 0
            for value
            in correlation_counters
        ):
            raise RuntimeError(
                "Web canonical processor returned "
                "invalid correlation counters"
            )

    @classmethod
    def _validate_batch_size(
        cls,
        value: int,
    ) -> int:
        if (
            isinstance(value, bool)
            or not isinstance(
                value,
                int,
            )
        ):
            raise TypeError(
                "batch_size must be an integer"
            )

        if not (
            1
            <= value
            <= cls.MAX_BATCH_SIZE
        ):
            raise ValueError(
                "batch_size must be between 1 "
                f"and {cls.MAX_BATCH_SIZE}"
            )

        return value

    @staticmethod
    def _validate_max_batches(
        value: int,
    ) -> int:
        if (
            isinstance(value, bool)
            or not isinstance(
                value,
                int,
            )
        ):
            raise TypeError(
                "max_batches must be an integer"
            )

        if value < 1:
            raise ValueError(
                "max_batches must be greater "
                "than zero"
            )

        return value

    @staticmethod
    def _build_result(
        *,
        counters: (
            _WebCanonicalJobCounters
        ),
        next_cursor: (
            _CursorT
            | None
        ),
        source_exhausted: bool,
        max_batches_reached: bool,
    ) -> (
        WebCanonicalCorrelationJobResult[
            _CursorT
        ]
    ):
        return (
            WebCanonicalCorrelationJobResult(
                batches_processed=(
                    counters
                    .batches_processed
                ),
                records_read=(
                    counters.records_read
                ),
                source_exhausted=(
                    source_exhausted
                ),
                max_batches_reached=(
                    max_batches_reached
                ),
                next_cursor=next_cursor,
                observations_received=(
                    counters
                    .observations_received
                ),
                components_built=(
                    counters.components_built
                ),
                canonical_created=(
                    counters.canonical_created
                ),
                canonical_updated=(
                    counters.canonical_updated
                ),
                canonical_persisted=(
                    counters.canonical_persisted
                ),
            )
        )

    @classmethod
    def _sanitize_error_summary(
        cls,
        error: Exception,
    ) -> str:
        summary = (
            f"{type(error).__name__}: "
            f"{error}"
        )

        summary = (
            _CONTROL_CHARACTER_PATTERN
            .sub(
                " ",
                summary,
            )
        )

        # Toutes les URL sont masquées, y compris celles
        # ne contenant aucun credential explicite.
        summary = _URL_PATTERN.sub(
            "[redacted-url]",
            summary,
        )

        summary = (
            _SECRET_ASSIGNMENT_PATTERN
            .sub(
                lambda match: (
                    f"{match.group(1)}=***"
                ),
                summary,
            )
        )

        summary = (
            _BEARER_TOKEN_PATTERN
            .sub(
                "Bearer ***",
                summary,
            )
        )

        return summary[
            :cls.MAX_LOG_SUMMARY_LENGTH
        ]