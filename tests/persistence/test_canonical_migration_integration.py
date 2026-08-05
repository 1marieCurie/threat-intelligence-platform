from __future__ import annotations

from pathlib import Path

from dotenv import load_dotenv


PROJECT_ROOT = Path(
    __file__
).resolve().parents[2]

load_dotenv(
    dotenv_path=PROJECT_ROOT / ".env",
    override=False,
)


from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from infrastructure.persistence.sqlalchemy import (
    create_ingestion_engine,
    create_session_factory,
)


pytestmark = pytest.mark.integration


CANONICAL_TABLES = (
    "canonical_vulnerability",
    "canonical_vulnerability_identifier",
    "canonical_vulnerability_evidence",
    "canonical_vulnerability_weakness",
    "canonical_web_indicator",
    "canonical_web_indicator_observation",
)


@pytest.fixture
def ingestion_session_factory(
) -> Iterator[sessionmaker[Session]]:
    engine = create_ingestion_engine()

    factory = create_session_factory(
        engine
    )

    try:
        yield factory
    finally:
        engine.dispose()


def _unique_cve_id() -> str:
    serial_number = (
        100_000_000
        + uuid4().int % 900_000_000
    )

    return (
        f"CVE-2026-{serial_number}"
    )


def _insert_vulnerability(
    session: Session,
    *,
    vulnerability_id: UUID,
    status: str | None = None,
    merged_into_id: UUID | None = None,
) -> None:
    now = datetime.now(UTC)

    if status is None:
        session.execute(
            text(
                """
                INSERT INTO
                    canonical.canonical_vulnerability (
                        id,
                        merged_into_id,
                        created_at,
                        updated_at
                    )
                VALUES (
                    :id,
                    :merged_into_id,
                    :created_at,
                    :updated_at
                )
                """
            ),
            {
                "id": vulnerability_id,
                "merged_into_id": (
                    merged_into_id
                ),
                "created_at": now,
                "updated_at": now,
            },
        )

        return

    session.execute(
        text(
            """
            INSERT INTO
                canonical.canonical_vulnerability (
                    id,
                    status,
                    merged_into_id,
                    created_at,
                    updated_at
                )
            VALUES (
                :id,
                :status,
                :merged_into_id,
                :created_at,
                :updated_at
            )
            """
        ),
        {
            "id": vulnerability_id,
            "status": status,
            "merged_into_id": (
                merged_into_id
            ),
            "created_at": now,
            "updated_at": now,
        },
    )


def _insert_identifier(
    session: Session,
    *,
    vulnerability_id: UUID,
    value: str,
    is_primary: bool = True,
) -> None:
    session.execute(
        text(
            """
            INSERT INTO
                canonical
                .canonical_vulnerability_identifier (
                    id,
                    vulnerability_id,
                    namespace,
                    value,
                    is_primary
                )
            VALUES (
                :id,
                :vulnerability_id,
                'CVE',
                :value,
                :is_primary
            )
            """
        ),
        {
            "id": uuid4(),
            "vulnerability_id": (
                vulnerability_id
            ),
            "value": value,
            "is_primary": is_primary,
        },
    )


def _insert_epss_evidence(
    session: Session,
    *,
    vulnerability_id: UUID,
    cve_id: str,
    observed_at: datetime,
    last_observed_at: datetime,
) -> None:
    session.execute(
        text(
            """
            INSERT INTO
                canonical
                .canonical_vulnerability_evidence (
                    id,
                    vulnerability_id,
                    source,
                    source_record_key,
                    normalized_record_id,
                    evidence_type,
                    correlation_rule,
                    observed_at,
                    last_observed_at,
                    correlation_confidence
                )
            VALUES (
                :id,
                :vulnerability_id,
                'epss',
                :source_record_key,
                :normalized_record_id,
                'epss_snapshot',
                'exact_cve',
                :observed_at,
                :last_observed_at,
                1
            )
            """
        ),
        {
            "id": uuid4(),
            "vulnerability_id": (
                vulnerability_id
            ),
            "source_record_key": cve_id,
            "normalized_record_id": cve_id,
            "observed_at": observed_at,
            "last_observed_at": (
                last_observed_at
            ),
        },
    )


def test_canonical_schema_contains_expected_tables(
    ingestion_session_factory: (
        sessionmaker[Session]
    ),
) -> None:
    with ingestion_session_factory() as session:
        table_names = set(
            session.execute(
                text(
                    """
                    SELECT table_name
                    FROM information_schema.tables
                    WHERE table_schema = 'canonical'
                      AND table_type = 'BASE TABLE'
                    """
                )
            )
            .scalars()
            .all()
        )

    assert table_names == set(
        CANONICAL_TABLES
    )


def test_canonical_tables_have_expected_columns(
    ingestion_session_factory: (
        sessionmaker[Session]
    ),
) -> None:
    with ingestion_session_factory() as session:
        rows = (
            session.execute(
                text(
                    """
                    SELECT
                        table_name,
                        column_name,
                        data_type,
                        is_nullable
                    FROM information_schema.columns
                    WHERE table_schema = 'canonical'
                    ORDER BY
                        table_name,
                        ordinal_position
                    """
                )
            )
            .mappings()
            .all()
        )

    columns_by_table: dict[
        str,
        dict[str, tuple[str, str]],
    ] = {}

    for row in rows:
        table_name = row[
            "table_name"
        ]

        column_name = row[
            "column_name"
        ]

        data_type = row[
            "data_type"
        ]

        is_nullable = row[
            "is_nullable"
        ]

        assert isinstance(
            table_name,
            str,
        )

        assert isinstance(
            column_name,
            str,
        )

        assert isinstance(
            data_type,
            str,
        )

        assert isinstance(
            is_nullable,
            str,
        )

        table_columns = (
            columns_by_table.setdefault(
                table_name,
                {},
            )
        )

        table_columns[
            column_name
        ] = (
            data_type,
            is_nullable,
        )

    assert columns_by_table[
        "canonical_vulnerability"
    ] == {
        "id": (
            "uuid",
            "NO",
        ),
        "status": (
            "character varying",
            "NO",
        ),
        "correlation_version": (
            "integer",
            "NO",
        ),
        "merged_into_id": (
            "uuid",
            "YES",
        ),
        "created_at": (
            "timestamp with time zone",
            "NO",
        ),
        "updated_at": (
            "timestamp with time zone",
            "NO",
        ),
    }

    assert columns_by_table[
        "canonical_vulnerability_identifier"
    ] == {
        "id": (
            "uuid",
            "NO",
        ),
        "vulnerability_id": (
            "uuid",
            "NO",
        ),
        "namespace": (
            "character varying",
            "NO",
        ),
        "value": (
            "character varying",
            "NO",
        ),
        "is_primary": (
            "boolean",
            "NO",
        ),
    }

    assert columns_by_table[
        "canonical_vulnerability_evidence"
    ] == {
        "id": (
            "uuid",
            "NO",
        ),
        "vulnerability_id": (
            "uuid",
            "NO",
        ),
        "source": (
            "character varying",
            "NO",
        ),
        "source_record_key": (
            "character varying",
            "NO",
        ),
        "normalized_record_id": (
            "character varying",
            "NO",
        ),
        "evidence_type": (
            "character varying",
            "NO",
        ),
        "correlation_rule": (
            "character varying",
            "NO",
        ),
        "observed_at": (
            "timestamp with time zone",
            "NO",
        ),
        "last_observed_at": (
            "timestamp with time zone",
            "NO",
        ),
        "source_published_at": (
            "timestamp with time zone",
            "YES",
        ),
        "source_modified_at": (
            "timestamp with time zone",
            "YES",
        ),
        "correlation_confidence": (
            "double precision",
            "NO",
        ),
        "record_hash": (
            "character varying",
            "YES",
        ),
    }

    assert columns_by_table[
        "canonical_vulnerability_weakness"
    ] == {
        "id": (
            "uuid",
            "NO",
        ),
        "vulnerability_id": (
            "uuid",
            "NO",
        ),
        "cwe_id": (
            "character varying",
            "NO",
        ),
        "source": (
            "character varying",
            "NO",
        ),
        "source_record_key": (
            "character varying",
            "NO",
        ),
        "normalized_record_id": (
            "character varying",
            "NO",
        ),
        "observed_at": (
            "timestamp with time zone",
            "NO",
        ),
        "last_observed_at": (
            "timestamp with time zone",
            "NO",
        ),
        "source_modified_at": (
            "timestamp with time zone",
            "YES",
        ),
    }


def test_database_contains_expected_constraints(
    ingestion_session_factory: (
        sessionmaker[Session]
    ),
) -> None:
    with ingestion_session_factory() as session:
        rows = (
            session.execute(
                text(
                    """
                    SELECT
                        relation_table.relname
                            AS table_name,
                        pg_get_constraintdef(
                            pg_constraint_row.oid,
                            true
                        ) AS definition
                    FROM pg_constraint
                        AS pg_constraint_row
                    JOIN pg_class
                        AS relation_table
                      ON relation_table.oid
                         = pg_constraint_row.conrelid
                    JOIN pg_namespace
                        AS schema_namespace
                      ON schema_namespace.oid
                         = relation_table.relnamespace
                    WHERE schema_namespace.nspname
                          = 'canonical'
                    ORDER BY
                        relation_table.relname,
                        pg_constraint_row.conname
                    """
                )
            )
            .mappings()
            .all()
        )

    definitions: dict[
        str,
        list[str],
    ] = {
        table_name: []
        for table_name in CANONICAL_TABLES
    }

    for row in rows:
        table_name = row[
            "table_name"
        ]

        definition = row[
            "definition"
        ]

        assert isinstance(
            table_name,
            str,
        )

        assert isinstance(
            definition,
            str,
        )

        assert table_name in definitions

        definitions[
            table_name
        ].append(
            definition
        )

    vulnerability_definitions = (
        definitions[
            "canonical_vulnerability"
        ]
    )

    assert any(
        (
            "status"
            in definition
            and
            "provisional"
            in definition
            and
            "merged"
            in definition
        )
        for definition
        in vulnerability_definitions
    )

    assert any(
        "correlation_version > 0"
        in definition
        for definition
        in vulnerability_definitions
    )

    assert any(
        "updated_at >= created_at"
        in definition
        for definition
        in vulnerability_definitions
    )

    assert any(
        (
            "FOREIGN KEY (merged_into_id)"
            in definition
            and
            (
                "ON DELETE RESTRICT"
                in definition
                or
                "REFERENCES canonical."
                "canonical_vulnerability"
                in definition
            )
        )
        for definition
        in vulnerability_definitions
    )

    identifier_definitions = (
        definitions[
            "canonical_vulnerability_identifier"
        ]
    )

    assert any(
        "UNIQUE (namespace, value)"
        in definition
        for definition
        in identifier_definitions
    )

    assert any(
        (
            "namespace"
            in definition
            and
            "CVE"
            in definition
            and
            "GHSA"
            in definition
        )
        for definition
        in identifier_definitions
    )

    assert any(
        (
            "FOREIGN KEY (vulnerability_id)"
            in definition
            and
            "ON DELETE CASCADE"
            in definition
        )
        for definition
        in identifier_definitions
    )

    evidence_definitions = (
        definitions[
            "canonical_vulnerability_evidence"
        ]
    )

    assert any(
        (
            "UNIQUE "
            "(source, source_record_key)"
            in definition
        )
        for definition
        in evidence_definitions
    )

    assert any(
        (
            "correlation_confidence >= 0"
            in definition
            and
            "correlation_confidence <= 1"
            in definition
        )
        for definition
        in evidence_definitions
    )

    assert any(
        (
            "last_observed_at >= observed_at"
            in definition
        )
        for definition
        in evidence_definitions
    )

    assert any(
        (
            "FOREIGN KEY (vulnerability_id)"
            in definition
            and
            "ON DELETE CASCADE"
            in definition
        )
        for definition
        in evidence_definitions
    )

    weakness_definitions = (
        definitions[
            "canonical_vulnerability_weakness"
        ]
    )

    assert any(
        (
            "UNIQUE "
            "(source, source_record_key, cwe_id)"
            in definition
        )
        for definition
        in weakness_definitions
    )

    assert any(
        (
            "last_observed_at >= observed_at"
            in definition
        )
        for definition
        in weakness_definitions
    )

    assert any(
        (
            "FOREIGN KEY (vulnerability_id)"
            in definition
            and
            "REFERENCES canonical."
            "canonical_vulnerability"
            in definition
            and
            "ON DELETE CASCADE"
            in definition
        )
        for definition
        in weakness_definitions
    )

    assert any(
        (
            "FOREIGN KEY (cwe_id)"
            in definition
            and
            "REFERENCES normalized.cwe_weakness"
            in definition
            and
            "ON DELETE CASCADE"
            not in definition
            and
            "ON DELETE SET NULL"
            not in definition
        )
        for definition
        in weakness_definitions
    )


def test_primary_identifier_index_is_unique_and_partial(
    ingestion_session_factory: (
        sessionmaker[Session]
    ),
) -> None:
    with ingestion_session_factory() as session:
        index_definition = (
            session.execute(
                text(
                    """
                    SELECT indexdef
                    FROM pg_indexes
                    WHERE schemaname = 'canonical'
                      AND indexname = (
                          'uq_canonical_vulnerability_'
                          'primary_identifier'
                      )
                    """
                )
            )
            .scalar_one()
        )

    assert isinstance(
        index_definition,
        str,
    )

    assert (
        "CREATE UNIQUE INDEX"
        in index_definition
    )

    assert (
        "vulnerability_id"
        in index_definition
    )

    assert (
        "WHERE (is_primary IS TRUE)"
        in index_definition
    )


def test_database_accepts_provisional_epss_only_vulnerability(
    ingestion_session_factory: (
        sessionmaker[Session]
    ),
) -> None:
    vulnerability_id = uuid4()
    cve_id = _unique_cve_id()

    observed_at = datetime.now(UTC)
    last_observed_at = (
        observed_at
        + timedelta(hours=1)
    )

    with ingestion_session_factory() as session:
        _insert_vulnerability(
            session,
            vulnerability_id=(
                vulnerability_id
            ),
        )

        _insert_identifier(
            session,
            vulnerability_id=(
                vulnerability_id
            ),
            value=cve_id,
        )

        _insert_epss_evidence(
            session,
            vulnerability_id=(
                vulnerability_id
            ),
            cve_id=cve_id,
            observed_at=observed_at,
            last_observed_at=(
                last_observed_at
            ),
        )

        row = (
            session.execute(
                text(
                    """
                    SELECT
                        vulnerability.status,
                        vulnerability.correlation_version,
                        identifier.value,
                        evidence.source,
                        evidence.evidence_type
                    FROM
                        canonical.canonical_vulnerability
                        AS vulnerability
                    JOIN
                        canonical
                        .canonical_vulnerability_identifier
                        AS identifier
                      ON identifier.vulnerability_id
                         = vulnerability.id
                    JOIN
                        canonical
                        .canonical_vulnerability_evidence
                        AS evidence
                      ON evidence.vulnerability_id
                         = vulnerability.id
                    WHERE vulnerability.id = :id
                    """
                ),
                {
                    "id": vulnerability_id,
                },
            )
            .mappings()
            .one()
        )

        assert row[
            "status"
        ] == "provisional"

        assert row[
            "correlation_version"
        ] == 1

        assert row[
            "value"
        ] == cve_id

        assert row[
            "source"
        ] == "epss"

        assert row[
            "evidence_type"
        ] == "epss_snapshot"

        session.rollback()


def test_database_rejects_identifier_shared_by_two_vulnerabilities(
    ingestion_session_factory: (
        sessionmaker[Session]
    ),
) -> None:
    first_vulnerability_id = uuid4()
    second_vulnerability_id = uuid4()

    cve_id = _unique_cve_id()

    with ingestion_session_factory() as session:
        _insert_vulnerability(
            session,
            vulnerability_id=(
                first_vulnerability_id
            ),
        )

        _insert_vulnerability(
            session,
            vulnerability_id=(
                second_vulnerability_id
            ),
        )

        _insert_identifier(
            session,
            vulnerability_id=(
                first_vulnerability_id
            ),
            value=cve_id,
        )

        with pytest.raises(
            IntegrityError,
        ):
            _insert_identifier(
                session,
                vulnerability_id=(
                    second_vulnerability_id
                ),
                value=cve_id,
            )

        session.rollback()


def test_database_rejects_two_primary_identifiers(
    ingestion_session_factory: (
        sessionmaker[Session]
    ),
) -> None:
    vulnerability_id = uuid4()

    with ingestion_session_factory() as session:
        _insert_vulnerability(
            session,
            vulnerability_id=(
                vulnerability_id
            ),
        )

        _insert_identifier(
            session,
            vulnerability_id=(
                vulnerability_id
            ),
            value=_unique_cve_id(),
        )

        with pytest.raises(
            IntegrityError,
        ):
            _insert_identifier(
                session,
                vulnerability_id=(
                    vulnerability_id
                ),
                value=_unique_cve_id(),
            )

        session.rollback()


def test_database_rejects_invalid_evidence_date_order(
    ingestion_session_factory: (
        sessionmaker[Session]
    ),
) -> None:
    vulnerability_id = uuid4()
    cve_id = _unique_cve_id()

    observed_at = datetime.now(UTC)
    last_observed_at = (
        observed_at
        - timedelta(minutes=1)
    )

    with ingestion_session_factory() as session:
        _insert_vulnerability(
            session,
            vulnerability_id=(
                vulnerability_id
            ),
        )

        _insert_identifier(
            session,
            vulnerability_id=(
                vulnerability_id
            ),
            value=cve_id,
        )

        with pytest.raises(
            IntegrityError,
        ):
            _insert_epss_evidence(
                session,
                vulnerability_id=(
                    vulnerability_id
                ),
                cve_id=cve_id,
                observed_at=observed_at,
                last_observed_at=(
                    last_observed_at
                ),
            )

        session.rollback()


def test_ingestion_role_has_least_privilege(
    ingestion_session_factory: (
        sessionmaker[Session]
    ),
) -> None:
    with ingestion_session_factory() as session:
        schema_permissions = (
            session.execute(
                text(
                    """
                    SELECT
                        has_schema_privilege(
                            current_user,
                            'canonical',
                            'USAGE'
                        ) AS can_use,
                        has_schema_privilege(
                            current_user,
                            'canonical',
                            'CREATE'
                        ) AS can_create
                    """
                )
            )
            .mappings()
            .one()
        )

        table_permissions = (
            session.execute(
                text(
                    """
                    SELECT
                        table_name,
                        has_table_privilege(
                            current_user,
                            format(
                                '%I.%I',
                                table_schema,
                                table_name
                            ),
                            'SELECT'
                        ) AS can_select,
                        has_table_privilege(
                            current_user,
                            format(
                                '%I.%I',
                                table_schema,
                                table_name
                            ),
                            'INSERT'
                        ) AS can_insert,
                        has_table_privilege(
                            current_user,
                            format(
                                '%I.%I',
                                table_schema,
                                table_name
                            ),
                            'UPDATE'
                        ) AS can_update,
                        has_table_privilege(
                            current_user,
                            format(
                                '%I.%I',
                                table_schema,
                                table_name
                            ),
                            'DELETE'
                        ) AS can_delete,
                        has_table_privilege(
                            current_user,
                            format(
                                '%I.%I',
                                table_schema,
                                table_name
                            ),
                            'TRUNCATE'
                        ) AS can_truncate
                    FROM information_schema.tables
                    WHERE table_schema = 'canonical'
                      AND table_type = 'BASE TABLE'
                    ORDER BY table_name
                    """
                )
            )
            .mappings()
            .all()
        )

    assert schema_permissions[
        "can_use"
    ] is True

    assert schema_permissions[
        "can_create"
    ] is False

    actual_table_names = {
        permissions[
            "table_name"
        ]
        for permissions
        in table_permissions
    }

    assert actual_table_names == set(
        CANONICAL_TABLES
    )

    assert len(
        table_permissions
    ) == len(
        CANONICAL_TABLES
    )

    for permissions in table_permissions:
        table_name = permissions[
            "table_name"
        ]

        assert isinstance(
            table_name,
            str,
        )

        assert permissions[
            "can_select"
        ] is True, table_name

        assert permissions[
            "can_insert"
        ] is True, table_name

        assert permissions[
            "can_update"
        ] is True, table_name

        assert permissions[
            "can_delete"
        ] is False, table_name

        assert permissions[
            "can_truncate"
        ] is False, table_name