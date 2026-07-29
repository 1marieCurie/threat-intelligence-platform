from __future__ import annotations

from sqlalchemy import (
    func,
    select,
    union_all,
)
from sqlalchemy.orm import Session

from infrastructure.persistence.models.normalized import (
    CisaKevVulnerabilityModel,
    GitHubAdvisoryVulnerabilityModel,
)


class SqlAlchemyVulnerabilityCWEReferenceRepository:
    """
    Lit les identifiants CWE présents dans CISA KEV et GHAD.

    PostgreSQL effectue l'unnest et la déduplication afin de ne pas
    charger les vulnérabilités complètes en mémoire.
    """

    def __init__(
        self,
        *,
        session: Session,
    ) -> None:
        if session is None:
            raise ValueError(
                "session must not be None"
            )

        self._session = session

    def list_distinct_ids(
        self,
        *,
        limit: int,
    ) -> list[str]:
        if isinstance(
            limit,
            bool,
        ):
            raise TypeError(
                "limit must be an integer"
            )

        if not isinstance(
            limit,
            int,
        ):
            raise TypeError(
                "limit must be an integer"
            )

        if limit <= 0:
            raise ValueError(
                "limit must be greater than zero"
            )

        cisa_ids = select(
            func.unnest(
                CisaKevVulnerabilityModel.cwes
            ).label(
                "cwe_id"
            )
        )

        github_ids = select(
            func.unnest(
                GitHubAdvisoryVulnerabilityModel
                .cwe_ids
            ).label(
                "cwe_id"
            )
        )

        combined = union_all(
            cisa_ids,
            github_ids,
        ).subquery()

        statement = (
            select(
                combined.c.cwe_id
            )
            .where(
                combined.c.cwe_id.is_not(
                    None
                )
            )
            .where(
                combined.c.cwe_id.op("~")(
                    r"^CWE-[1-9][0-9]*$"
                )
            )
            .distinct()
            .order_by(
                combined.c.cwe_id
            )
            .limit(
                limit
            )
        )

        values = (
            self._session
            .execute(statement)
            .scalars()
            .all()
        )

        return [
            value
            for value in values
            if isinstance(
                value,
                str,
            )
        ]