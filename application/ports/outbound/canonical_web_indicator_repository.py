from __future__ import annotations

from collections.abc import Iterable
from typing import (
    Protocol,
    runtime_checkable,
)
from uuid import UUID

from application.models.canonical_url_identity import (
    CanonicalURLIdentity,
)
from domain.canonical_web_indicator import (
    CanonicalWebIndicator,
)
from domain.web_indicator_observation import (
    WebIndicatorObservation,
)


WebIndicatorIdentityKey = tuple[
    int,
    str,
]

WebIndicatorObservationKey = tuple[
    str,
    str,
]


class CanonicalWebIndicatorRepositoryError(
    RuntimeError
):
    """
    Erreur générique du repository canonique Web.

    Les erreurs SQLAlchemy ou PostgreSQL ne doivent pas
    traverser cette frontière applicative.
    """


class CanonicalWebIndicatorConflictError(
    CanonicalWebIndicatorRepositoryError
):
    """
    Signale une violation d'identité ou de concurrence.

    Exemples :

    - une observation source attribuée à deux URLs ;
    - une empreinte attribuée à deux valeurs canoniques ;
    - une mise à jour concurrente incohérente.
    """


@runtime_checkable
class CanonicalWebIndicatorRepository(
    Protocol
):
    """
    Port de persistance des indicateurs Web canoniques.

    La décision de corrélation appartient au service
    applicatif. Le repository persiste et protège les
    contraintes d'identité.
    """

    def find_by_id(
        self,
        indicator_id: UUID,
    ) -> CanonicalWebIndicator | None:
        ...

    def find_many_by_ids(
        self,
        indicator_ids: Iterable[UUID],
    ) -> dict[
        UUID,
        CanonicalWebIndicator,
    ]:
        """
        Charge plusieurs agrégats de manière groupée.
        """
        ...

    def find_many_by_identities(
        self,
        identities: Iterable[
            CanonicalURLIdentity
        ],
    ) -> dict[
        WebIndicatorIdentityKey,
        CanonicalWebIndicator,
    ]:
        """
        Résout les agrégats par identité exacte :

            (
                canonicalization_version,
                value_hash,
            )
        """
        ...

    def find_many_by_observations(
        self,
        observations: Iterable[
            WebIndicatorObservation
        ],
    ) -> dict[
        WebIndicatorObservationKey,
        CanonicalWebIndicator,
    ]:
        """
        Résout les observations déjà persistées par :

            (
                source,
                source_record_key,
            )
        """
        ...

    def upsert_many(
        self,
        indicators: Iterable[
            CanonicalWebIndicator
        ],
    ) -> int:
        """
        Insère ou met à jour plusieurs agrégats.

        Les observations absentes de l'entrée mais déjà
        persistées doivent être conservées.

        Retourne le nombre d'UUID uniques traités.
        """
        ...