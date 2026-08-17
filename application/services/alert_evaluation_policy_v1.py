from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID


@dataclass(
    frozen=True,
    slots=True,
)
class AlertCandidate:
    alert_type: str
    deduplication_key: str


class AlertEvaluationPolicyV1:
    """
    Politique pure et déterministe d'évaluation des alertes V1.

    Règles :
    1. nouvelle exposition confirmée CRITICAL ;
    2. exposition confirmée entrant dans KEV ;
    3. exposition confirmée passant
       LOW|MEDIUM|HIGH -> CRITICAL.

    Les expositions potential ne déclenchent
    aucune alerte critique V1.
    """

    POLICY_VERSION = "1.0.0"

    NEW_CONFIRMED_CRITICAL = (
        "new_confirmed_critical_exposure"
    )

    CONFIRMED_ENTERED_KEV = (
        "confirmed_exposure_entered_kev"
    )

    PRIORITY_TO_CRITICAL = (
        "priority_transition_to_critical"
    )

    _PRIORITIES = frozenset(
        {
            "LOW",
            "MEDIUM",
            "HIGH",
            "CRITICAL",
        }
    )

    _PREVIOUS_CRITICAL_TRANSITION_PRIORITIES = (
        frozenset(
            {
                "LOW",
                "MEDIUM",
                "HIGH",
            }
        )
    )

    def evaluate(
        self,
        *,
        exposure_id: UUID,
        applicability_status: str,
        is_new_exposure: bool,
        previous_priority: str | None,
        current_priority: str,
        previous_is_kev: bool | None,
        current_is_kev: bool,
    ) -> tuple[
        AlertCandidate,
        ...,
    ]:
        self._validate_uuid(
            exposure_id
        )

        applicability = (
            self._normalize_applicability(
                applicability_status
            )
        )

        previous_priority = (
            self._normalize_optional_priority(
                previous_priority
            )
        )

        current_priority = (
            self._normalize_priority(
                current_priority
            )
        )

        if not isinstance(
            is_new_exposure,
            bool,
        ):
            raise TypeError(
                "is_new_exposure must be a bool"
            )

        if (
            previous_is_kev is not None
            and not isinstance(
                previous_is_kev,
                bool,
            )
        ):
            raise TypeError(
                "previous_is_kev must be "
                "a bool or None"
            )

        if not isinstance(
            current_is_kev,
            bool,
        ):
            raise TypeError(
                "current_is_kev must be a bool"
            )

        # V1 :
        # une exposition potential ne génère
        # pas automatiquement d'alerte critique.
        if applicability != "confirmed":
            return ()

        candidates: list[
            AlertCandidate
        ] = []

        # =====================================================
        # 1. Nouvelle exposition critique confirmée.
        # =====================================================
        if (
            is_new_exposure
            and current_priority
            == "CRITICAL"
        ):
            candidates.append(
                self._candidate(
                    exposure_id=exposure_id,
                    alert_type=(
                        self.NEW_CONFIRMED_CRITICAL
                    ),
                )
            )

        # =====================================================
        # 2. Exposition confirmée entrant dans KEV.
        #
        # Il faut une vraie transition :
        # False -> True.
        #
        # Une exposition nouvellement créée avec KEV=True
        # n'est pas considérée comme "entrant" dans KEV.
        # =====================================================
        if (
            not is_new_exposure
            and previous_is_kev is False
            and current_is_kev is True
        ):
            candidates.append(
                self._candidate(
                    exposure_id=exposure_id,
                    alert_type=(
                        self.CONFIRMED_ENTERED_KEV
                    ),
                )
            )

        # =====================================================
        # 3. Transition vers CRITICAL.
        #
        # LOW|MEDIUM|HIGH -> CRITICAL uniquement.
        #
        # MEDIUM -> HIGH ne déclenche rien.
        # =====================================================
        if (
            not is_new_exposure
            and previous_priority
            in (
                self
                ._PREVIOUS_CRITICAL_TRANSITION_PRIORITIES
            )
            and current_priority
            == "CRITICAL"
        ):
            candidates.append(
                self._candidate(
                    exposure_id=exposure_id,
                    alert_type=(
                        self.PRIORITY_TO_CRITICAL
                    ),
                )
            )

        return tuple(
            candidates
        )

    @classmethod
    def _candidate(
        cls,
        *,
        exposure_id: UUID,
        alert_type: str,
    ) -> AlertCandidate:
        """
        Clé déterministe.

        La DB ajoute déjà organization_id dans
        la contrainte unique, donc exposure_id +
        alert_type suffisent pour la V1.
        """

        deduplication_key = (
            f"alert/v1:"
            f"{alert_type}:"
            f"{exposure_id}"
        )

        if len(
            deduplication_key
        ) > 255:
            raise ValueError(
                "deduplication_key exceeds "
                "255 characters"
            )

        return AlertCandidate(
            alert_type=alert_type,
            deduplication_key=(
                deduplication_key
            ),
        )

    @classmethod
    def _normalize_priority(
        cls,
        value: str,
    ) -> str:
        if not isinstance(
            value,
            str,
        ):
            raise TypeError(
                "current_priority must "
                "be a string"
            )

        normalized = (
            value
            .strip()
            .upper()
        )

        if normalized not in cls._PRIORITIES:
            raise ValueError(
                "current_priority must be one of "
                "LOW, MEDIUM, HIGH, CRITICAL"
            )

        return normalized

    @classmethod
    def _normalize_optional_priority(
        cls,
        value: str | None,
    ) -> str | None:
        if value is None:
            return None

        if not isinstance(
            value,
            str,
        ):
            raise TypeError(
                "previous_priority must be "
                "a string or None"
            )

        normalized = (
            value
            .strip()
            .upper()
        )

        if normalized not in cls._PRIORITIES:
            raise ValueError(
                "previous_priority must be "
                "LOW, MEDIUM, HIGH, "
                "CRITICAL or None"
            )

        return normalized

    @staticmethod
    def _normalize_applicability(
        value: str,
    ) -> str:
        if not isinstance(
            value,
            str,
        ):
            raise TypeError(
                "applicability_status "
                "must be a string"
            )

        normalized = (
            value
            .strip()
            .lower()
        )

        if normalized not in {
            "confirmed",
            "potential",
        }:
            raise ValueError(
                "applicability_status must be "
                "confirmed or potential"
            )

        return normalized

    @staticmethod
    def _validate_uuid(
        value: UUID,
    ) -> None:
        if not isinstance(
            value,
            UUID,
        ):
            raise TypeError(
                "exposure_id must be a UUID"
            )