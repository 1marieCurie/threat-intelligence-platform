from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Final

from dotenv import load_dotenv
from sqlalchemy import (
    Connection,
    Engine,
    create_engine,
    inspect,
    text,
)
from sqlalchemy.engine import Inspector
from sqlalchemy.exc import SQLAlchemyError


# ============================================================
# Chargement sécurisé de l'environnement
# ============================================================

PROJECT_ROOT: Final[Path] = Path(
    __file__
).resolve().parents[1]

ENV_FILE: Final[Path] = PROJECT_ROOT / ".env"

load_dotenv(
    dotenv_path=ENV_FILE,
    override=False,
)


# ============================================================
# Configuration
# ============================================================

DEFAULT_OUTPUT_DIRECTORY: Final[Path] = (
    PROJECT_ROOT
    / "docs"
    / "database"
)

DEFAULT_MANAGED_SCHEMAS: Final[tuple[str, ...]] = (
    "threat_intel",
    "ops",
    "raw",
    "normalized",
    "canonical",
)

SYSTEM_SCHEMAS: Final[frozenset[str]] = frozenset(
    {
        "information_schema",
        "pg_catalog",
        "pg_toast",
    }
)

# Les valeurs réelles observées dans
# canonical_vulnerability_evidence.source peuvent évoluer.
# Elles sont normalisées en minuscules avant comparaison.
EPSS_SOURCE_NAMES: Final[tuple[str, ...]] = (
    "epss",
    "first",
)

MARKDOWN_FILE_NAME: Final[str] = (
    "database_documentation.md"
)

JSON_FILE_NAME: Final[str] = (
    "database_documentation.json"
)

SAFE_IDENTIFIER_PATTERN: Final[
    re.Pattern[str]
] = re.compile(
    r"^[A-Za-z_][A-Za-z0-9_$]*$"
)


# ============================================================
# Modèles de documentation
# ============================================================

@dataclass(slots=True)
class ColumnDocumentation:
    name: str
    data_type: str
    nullable: bool
    default: str | None
    autoincrement: str | bool | None
    comment: str | None


@dataclass(slots=True)
class ConstraintDocumentation:
    name: str
    constraint_type: str
    definition: str


@dataclass(slots=True)
class IndexDocumentation:
    name: str
    definition: str
    unique: bool
    primary: bool
    valid: bool


@dataclass(slots=True)
class TriggerDocumentation:
    name: str
    enabled: str
    definition: str


@dataclass(slots=True)
class TableDocumentation:
    schema_name: str
    table_name: str
    object_type: str
    comment: str | None
    exact_row_count: int | None
    estimated_row_count: int | None
    total_size_bytes: int | None
    table_size_bytes: int | None
    indexes_size_bytes: int | None
    columns: list[ColumnDocumentation] = field(
        default_factory=list
    )
    constraints: list[
        ConstraintDocumentation
    ] = field(
        default_factory=list
    )
    indexes: list[IndexDocumentation] = field(
        default_factory=list
    )
    triggers: list[TriggerDocumentation] = field(
        default_factory=list
    )


@dataclass(slots=True)
class SchemaDocumentation:
    name: str
    owner: str | None
    comment: str | None
    tables: list[TableDocumentation] = field(
        default_factory=list
    )


@dataclass(slots=True)
class DatabaseObjectDocumentation:
    schema_name: str
    object_name: str
    object_type: str
    owner: str | None
    definition: str | None


@dataclass(slots=True)
class CanonicalMetrics:
    total_canonical_vulnerabilities: int
    canonical_vulnerabilities_by_status: dict[
        str,
        int,
    ]

    total_vulnerabilities_with_cve: int
    total_vulnerabilities_without_cve: int
    total_primary_cve_identifiers: int
    total_primary_ghsa_identifiers: int

    cve_with_cwe_enrichment: int
    cve_without_cwe_enrichment: int

    cve_with_epss_evidence: int
    cve_without_epss_evidence: int

    cve_with_any_enrichment: int
    cve_without_any_enrichment: int

    multi_source_cve: int
    single_source_cve: int

    total_canonical_web_indicators: int
    total_web_indicator_observations: int

    enrichment_definition: str


@dataclass(slots=True)
class DatabaseDocumentation:
    generated_at_utc: str
    database_name: str
    database_user: str
    server_version: str
    alembic_version: str | None
    exact_counts_enabled: bool
    schemas: list[SchemaDocumentation]
    other_objects: list[
        DatabaseObjectDocumentation
    ]
    canonical_metrics: CanonicalMetrics | None
    warnings: list[str]


# ============================================================
# Helpers
# ============================================================

def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Génère une documentation structurée "
            "de la base PostgreSQL du projet."
        ),
    )

    parser.add_argument(
        "--output-directory",
        type=Path,
        default=DEFAULT_OUTPUT_DIRECTORY,
        help=(
            "Répertoire de sortie. "
            "Défaut : docs/database"
        ),
    )

    parser.add_argument(
        "--schemas",
        nargs="+",
        default=list(DEFAULT_MANAGED_SCHEMAS),
        help=(
            "Schémas PostgreSQL à documenter."
        ),
    )

    parser.add_argument(
        "--estimated-counts-only",
        action="store_true",
        help=(
            "N'exécute pas COUNT(*) sur chaque table. "
            "Utilise uniquement les estimations PostgreSQL."
        ),
    )

    return parser.parse_args()


def get_database_url() -> str:
    """
    Retourne exclusivement l'URL du rôle documentaire.

    Aucun repli vers le rôle applicatif, d'ingestion ou de
    migration n'est autorisé afin de conserver le principe
    du moindre privilège.
    """

    database_url = os.environ.get(
        "DOCUMENTATION_DATABASE_URL"
    )

    if not database_url:
        raise RuntimeError(
            "DOCUMENTATION_DATABASE_URL doit être "
            "défini dans le fichier .env."
        )

    return database_url


def create_database_engine(
    database_url: str,
) -> Engine:
    return create_engine(
        database_url,
        pool_pre_ping=True,
        pool_recycle=300,
        future=True,
        connect_args={
            "application_name": (
                "database_documentation_generator"
            ),
        },
    )


def validate_schema_names(
    schemas: list[str],
) -> list[str]:
    validated: list[str] = []

    for schema_name in schemas:
        if not SAFE_IDENTIFIER_PATTERN.fullmatch(
            schema_name
        ):
            raise ValueError(
                "Nom de schéma PostgreSQL invalide : "
                f"{schema_name!r}"
            )

        if (
            schema_name in SYSTEM_SCHEMAS
            or schema_name.startswith("pg_")
        ):
            raise ValueError(
                "Le script ne doit pas documenter "
                "les schémas système : "
                f"{schema_name!r}"
            )

        validated.append(schema_name)

    return sorted(set(validated))


def quote_identifier(
    connection: Connection,
    identifier: str,
) -> str:
    return (
        connection.dialect.identifier_preparer
        .quote_identifier(identifier)
    )


def qualified_table_name(
    connection: Connection,
    schema_name: str,
    table_name: str,
) -> str:
    return (
        f"{quote_identifier(connection, schema_name)}."
        f"{quote_identifier(connection, table_name)}"
    )


def execute_scalar_int(
    connection: Connection,
    sql: str,
    parameters: dict[str, Any] | None = None,
) -> int:
    value = connection.execute(
        text(sql),
        parameters or {},
    ).scalar_one()

    return int(value)


def format_bytes(
    value: int | None,
) -> str:
    if value is None:
        return "Non disponible"

    units = (
        "B",
        "KiB",
        "MiB",
        "GiB",
        "TiB",
    )

    current = float(value)

    for unit in units:
        if current < 1024 or unit == units[-1]:
            return f"{current:.2f} {unit}"

        current /= 1024

    return f"{value} B"


def markdown_escape(
    value: Any,
) -> str:
    if value is None:
        return ""

    rendered = str(value)

    return (
        rendered
        .replace("\\", "\\\\")
        .replace("|", "\\|")
        .replace("\n", "<br>")
    )


def markdown_code(
    value: Any,
) -> str:
    if value is None:
        return "—"

    rendered = str(value).strip()

    if not rendered:
        return "—"

    return f"`{markdown_escape(rendered)}`"


def markdown_anchor(
    value: str,
) -> str:
    normalized = re.sub(
        r"[^a-z0-9]+",
        "-",
        value.lower(),
    )

    return normalized.strip("-")


# ============================================================
# Métadonnées générales
# ============================================================

def load_database_identity(
    connection: Connection,
) -> tuple[str, str, str]:
    row = connection.execute(
        text(
            """
            SELECT
                current_database() AS database_name,
                current_user AS database_user,
                current_setting(
                    'server_version'
                ) AS server_version
            """
        )
    ).mappings().one()

    return (
        str(row["database_name"]),
        str(row["database_user"]),
        str(row["server_version"]),
    )
    

EXPECTED_DATABASE_ROLE: Final[str] = (
    "threat_intel_reader"
)


def validate_database_role(
    connection: Connection,
) -> None:
    """
    Empêche l'exécution avec un rôle différent du rôle
    documentaire attendu.

    Cette vérification évite d'utiliser accidentellement
    migrator, owner, ingestion ou app.
    """

    current_role = connection.execute(
        text(
            """
            SELECT current_user
            """
        )
    ).scalar_one()

    if current_role != EXPECTED_DATABASE_ROLE:
        raise RuntimeError(
            "Le générateur de documentation doit être "
            "exécuté avec le rôle PostgreSQL "
            f"{EXPECTED_DATABASE_ROLE!r}. "
            f"Rôle actuel : {current_role!r}."
        )

def load_alembic_version(
    connection: Connection,
) -> str | None:
    exists = connection.execute(
        text(
            """
            SELECT EXISTS (
                SELECT 1
                FROM information_schema.tables
                WHERE table_schema = 'threat_intel'
                  AND table_name = 'alembic_version'
            )
            """
        )
    ).scalar_one()

    if not exists:
        return None

    return connection.execute(
        text(
            """
            SELECT version_num
            FROM threat_intel.alembic_version
            LIMIT 1
            """
        )
    ).scalar_one_or_none()


# ============================================================
# Schémas
# ============================================================

def load_schema_metadata(
    connection: Connection,
    schema_name: str,
) -> tuple[str | None, str | None]:
    row = connection.execute(
        text(
            """
            SELECT
                pg_get_userbyid(
                    namespace.nspowner
                ) AS owner,
                obj_description(
                    namespace.oid,
                    'pg_namespace'
                ) AS comment
            FROM pg_namespace AS namespace
            WHERE namespace.nspname = :schema_name
            """
        ),
        {
            "schema_name": schema_name,
        },
    ).mappings().one_or_none()

    if row is None:
        return None, None

    return (
        (
            str(row["owner"])
            if row["owner"] is not None
            else None
        ),
        (
            str(row["comment"])
            if row["comment"] is not None
            else None
        ),
    )


# ============================================================
# Tables et colonnes
# ============================================================

def load_table_storage_metadata(
    connection: Connection,
    schema_name: str,
    table_name: str,
) -> dict[str, Any]:
    row = connection.execute(
        text(
            """
            SELECT
                relation.reltuples::bigint
                    AS estimated_row_count,
                pg_total_relation_size(
                    relation.oid
                ) AS total_size_bytes,
                pg_relation_size(
                    relation.oid
                ) AS table_size_bytes,
                pg_indexes_size(
                    relation.oid
                ) AS indexes_size_bytes,
                obj_description(
                    relation.oid,
                    'pg_class'
                ) AS comment
            FROM pg_class AS relation
            JOIN pg_namespace AS namespace
              ON namespace.oid
                 = relation.relnamespace
            WHERE namespace.nspname = :schema_name
              AND relation.relname = :table_name
            """
        ),
        {
            "schema_name": schema_name,
            "table_name": table_name,
        },
    ).mappings().one_or_none()

    if row is None:
        return {
            "estimated_row_count": None,
            "total_size_bytes": None,
            "table_size_bytes": None,
            "indexes_size_bytes": None,
            "comment": None,
        }

    return dict(row)


def load_exact_row_count(
    connection: Connection,
    schema_name: str,
    table_name: str,
) -> int:
    qualified_name = qualified_table_name(
        connection,
        schema_name,
        table_name,
    )

    return execute_scalar_int(
        connection,
        f"SELECT COUNT(*) FROM {qualified_name}",
    )


def load_columns(
    inspector: Inspector,
    schema_name: str,
    table_name: str,
) -> list[ColumnDocumentation]:
    columns: list[ColumnDocumentation] = []

    for column in inspector.get_columns(
        table_name,
        schema=schema_name,
    ):
        columns.append(
            ColumnDocumentation(
                name=str(column["name"]),
                data_type=str(column["type"]),
                nullable=bool(
                    column.get("nullable", True)
                ),
                default=(
                    str(column.get("default"))
                    if column.get("default")
                    is not None
                    else None
                ),
                autoincrement=column.get(
                    "autoincrement"
                ),
                comment=(
                    str(column.get("comment"))
                    if column.get("comment")
                    is not None
                    else None
                ),
            )
        )

    return columns


def load_constraints(
    connection: Connection,
    schema_name: str,
    table_name: str,
) -> list[ConstraintDocumentation]:
    rows = connection.execute(
        text(
            """
            SELECT
                constraint_row.conname AS name,
                CASE constraint_row.contype
                    WHEN 'p' THEN 'PRIMARY KEY'
                    WHEN 'f' THEN 'FOREIGN KEY'
                    WHEN 'u' THEN 'UNIQUE'
                    WHEN 'c' THEN 'CHECK'
                    WHEN 'x' THEN 'EXCLUSION'
                    ELSE constraint_row.contype::text
                END AS constraint_type,
                pg_get_constraintdef(
                    constraint_row.oid,
                    true
                ) AS definition
            FROM pg_constraint
                AS constraint_row
            JOIN pg_class AS relation
              ON relation.oid
                 = constraint_row.conrelid
            JOIN pg_namespace AS namespace
              ON namespace.oid
                 = relation.relnamespace
            WHERE namespace.nspname = :schema_name
              AND relation.relname = :table_name
            ORDER BY
                constraint_type,
                constraint_row.conname
            """
        ),
        {
            "schema_name": schema_name,
            "table_name": table_name,
        },
    ).mappings().all()

    return [
        ConstraintDocumentation(
            name=str(row["name"]),
            constraint_type=str(
                row["constraint_type"]
            ),
            definition=str(row["definition"]),
        )
        for row in rows
    ]


def load_indexes(
    connection: Connection,
    schema_name: str,
    table_name: str,
) -> list[IndexDocumentation]:
    rows = connection.execute(
        text(
            """
            SELECT
                index_relation.relname AS name,
                pg_get_indexdef(
                    index_relation.oid
                ) AS definition,
                index_row.indisunique AS is_unique,
                index_row.indisprimary AS is_primary,
                index_row.indisvalid AS is_valid
            FROM pg_index AS index_row
            JOIN pg_class AS table_relation
              ON table_relation.oid
                 = index_row.indrelid
            JOIN pg_class AS index_relation
              ON index_relation.oid
                 = index_row.indexrelid
            JOIN pg_namespace AS namespace
              ON namespace.oid
                 = table_relation.relnamespace
            WHERE namespace.nspname = :schema_name
              AND table_relation.relname = :table_name
            ORDER BY index_relation.relname
            """
        ),
        {
            "schema_name": schema_name,
            "table_name": table_name,
        },
    ).mappings().all()

    return [
        IndexDocumentation(
            name=str(row["name"]),
            definition=str(row["definition"]),
            unique=bool(row["is_unique"]),
            primary=bool(row["is_primary"]),
            valid=bool(row["is_valid"]),
        )
        for row in rows
    ]


def load_triggers(
    connection: Connection,
    schema_name: str,
    table_name: str,
) -> list[TriggerDocumentation]:
    rows = connection.execute(
        text(
            """
            SELECT
                trigger_row.tgname AS name,
                CASE trigger_row.tgenabled
                    WHEN 'O' THEN 'enabled'
                    WHEN 'D' THEN 'disabled'
                    WHEN 'R' THEN 'replica'
                    WHEN 'A' THEN 'always'
                    ELSE trigger_row.tgenabled::text
                END AS enabled,
                pg_get_triggerdef(
                    trigger_row.oid,
                    true
                ) AS definition
            FROM pg_trigger AS trigger_row
            JOIN pg_class AS relation
              ON relation.oid
                 = trigger_row.tgrelid
            JOIN pg_namespace AS namespace
              ON namespace.oid
                 = relation.relnamespace
            WHERE namespace.nspname = :schema_name
              AND relation.relname = :table_name
              AND NOT trigger_row.tgisinternal
            ORDER BY trigger_row.tgname
            """
        ),
        {
            "schema_name": schema_name,
            "table_name": table_name,
        },
    ).mappings().all()

    return [
        TriggerDocumentation(
            name=str(row["name"]),
            enabled=str(row["enabled"]),
            definition=str(row["definition"]),
        )
        for row in rows
    ]


def load_table_documentation(
    connection: Connection,
    inspector: Inspector,
    schema_name: str,
    table_name: str,
    *,
    exact_counts_enabled: bool,
) -> TableDocumentation:
    storage = load_table_storage_metadata(
        connection,
        schema_name,
        table_name,
    )

    exact_row_count: int | None = None

    if exact_counts_enabled:
        exact_row_count = load_exact_row_count(
            connection,
            schema_name,
            table_name,
        )

    return TableDocumentation(
        schema_name=schema_name,
        table_name=table_name,
        object_type="table",
        comment=storage["comment"],
        exact_row_count=exact_row_count,
        estimated_row_count=(
            int(storage["estimated_row_count"])
            if storage["estimated_row_count"]
            is not None
            else None
        ),
        total_size_bytes=(
            int(storage["total_size_bytes"])
            if storage["total_size_bytes"]
            is not None
            else None
        ),
        table_size_bytes=(
            int(storage["table_size_bytes"])
            if storage["table_size_bytes"]
            is not None
            else None
        ),
        indexes_size_bytes=(
            int(storage["indexes_size_bytes"])
            if storage["indexes_size_bytes"]
            is not None
            else None
        ),
        columns=load_columns(
            inspector,
            schema_name,
            table_name,
        ),
        constraints=load_constraints(
            connection,
            schema_name,
            table_name,
        ),
        indexes=load_indexes(
            connection,
            schema_name,
            table_name,
        ),
        triggers=load_triggers(
            connection,
            schema_name,
            table_name,
        ),
    )


def load_schemas(
    connection: Connection,
    inspector: Inspector,
    managed_schemas: list[str],
    *,
    exact_counts_enabled: bool,
    warnings: list[str],
) -> list[SchemaDocumentation]:
    existing_schemas = set(
        inspector.get_schema_names()
    )

    documentation: list[
        SchemaDocumentation
    ] = []

    for schema_name in managed_schemas:
        if schema_name not in existing_schemas:
            warnings.append(
                "Schéma absent de la base : "
                f"{schema_name}"
            )
            continue

        owner, comment = load_schema_metadata(
            connection,
            schema_name,
        )

        tables: list[TableDocumentation] = []

        for table_name in sorted(
            inspector.get_table_names(
                schema=schema_name
            )
        ):
            tables.append(
                load_table_documentation(
                    connection,
                    inspector,
                    schema_name,
                    table_name,
                    exact_counts_enabled=(
                        exact_counts_enabled
                    ),
                )
            )

        documentation.append(
            SchemaDocumentation(
                name=schema_name,
                owner=owner,
                comment=comment,
                tables=tables,
            )
        )

    return documentation


# ============================================================
# Autres objets PostgreSQL
# ============================================================

def load_other_objects(
    connection: Connection,
    managed_schemas: list[str],
) -> list[DatabaseObjectDocumentation]:
    rows = connection.execute(
        text(
            """
            SELECT
                namespace.nspname AS schema_name,
                relation.relname AS object_name,
                CASE relation.relkind
                    WHEN 'v' THEN 'view'
                    WHEN 'm' THEN 'materialized_view'
                    WHEN 'S' THEN 'sequence'
                    WHEN 'f' THEN 'foreign_table'
                    WHEN 'p' THEN 'partitioned_table'
                    WHEN 'I' THEN 'partitioned_index'
                    ELSE relation.relkind::text
                END AS object_type,
                pg_get_userbyid(
                    relation.relowner
                ) AS owner,
                CASE
                    WHEN relation.relkind = 'v'
                    THEN pg_get_viewdef(
                        relation.oid,
                        true
                    )
                    WHEN relation.relkind = 'm'
                    THEN pg_get_viewdef(
                        relation.oid,
                        true
                    )
                    ELSE NULL
                END AS definition
            FROM pg_class AS relation
            JOIN pg_namespace AS namespace
              ON namespace.oid
                 = relation.relnamespace
            WHERE namespace.nspname
                  = ANY(:schemas)
              AND relation.relkind
                  IN ('v', 'm', 'S', 'f', 'p', 'I')
            ORDER BY
                namespace.nspname,
                object_type,
                relation.relname
            """
        ),
        {
            "schemas": managed_schemas,
        },
    ).mappings().all()

    objects = [
        DatabaseObjectDocumentation(
            schema_name=str(row["schema_name"]),
            object_name=str(row["object_name"]),
            object_type=str(row["object_type"]),
            owner=(
                str(row["owner"])
                if row["owner"] is not None
                else None
            ),
            definition=(
                str(row["definition"])
                if row["definition"] is not None
                else None
            ),
        )
        for row in rows
    ]

    function_rows = connection.execute(
        text(
            """
            SELECT
                namespace.nspname AS schema_name,
                procedure.proname AS object_name,
                CASE procedure.prokind
                    WHEN 'p' THEN 'procedure'
                    WHEN 'a' THEN 'aggregate'
                    WHEN 'w' THEN 'window_function'
                    ELSE 'function'
                END AS object_type,
                pg_get_userbyid(
                    procedure.proowner
                ) AS owner,
                pg_get_functiondef(
                    procedure.oid
                ) AS definition
            FROM pg_proc AS procedure
            JOIN pg_namespace AS namespace
              ON namespace.oid
                 = procedure.pronamespace
            WHERE namespace.nspname
                  = ANY(:schemas)
            ORDER BY
                namespace.nspname,
                procedure.proname
            """
        ),
        {
            "schemas": managed_schemas,
        },
    ).mappings().all()

    objects.extend(
        DatabaseObjectDocumentation(
            schema_name=str(row["schema_name"]),
            object_name=str(row["object_name"]),
            object_type=str(row["object_type"]),
            owner=(
                str(row["owner"])
                if row["owner"] is not None
                else None
            ),
            definition=(
                str(row["definition"])
                if row["definition"] is not None
                else None
            ),
        )
        for row in function_rows
    )

    enum_rows = connection.execute(
        text(
            """
            SELECT
                namespace.nspname AS schema_name,
                type_row.typname AS object_name,
                'enum' AS object_type,
                pg_get_userbyid(
                    type_row.typowner
                ) AS owner,
                string_agg(
                    enum_row.enumlabel,
                    ', '
                    ORDER BY enum_row.enumsortorder
                ) AS definition
            FROM pg_type AS type_row
            JOIN pg_namespace AS namespace
              ON namespace.oid
                 = type_row.typnamespace
            JOIN pg_enum AS enum_row
              ON enum_row.enumtypid
                 = type_row.oid
            WHERE namespace.nspname
                  = ANY(:schemas)
            GROUP BY
                namespace.nspname,
                type_row.typname,
                type_row.typowner
            ORDER BY
                namespace.nspname,
                type_row.typname
            """
        ),
        {
            "schemas": managed_schemas,
        },
    ).mappings().all()

    objects.extend(
        DatabaseObjectDocumentation(
            schema_name=str(row["schema_name"]),
            object_name=str(row["object_name"]),
            object_type="enum",
            owner=(
                str(row["owner"])
                if row["owner"] is not None
                else None
            ),
            definition=(
                str(row["definition"])
                if row["definition"] is not None
                else None
            ),
        )
        for row in enum_rows
    )

    return sorted(
        objects,
        key=lambda item: (
            item.schema_name,
            item.object_type,
            item.object_name,
        ),
    )


# ============================================================
# Métriques canoniques
# ============================================================

def canonical_tables_exist(
    inspector: Inspector,
) -> bool:
    existing = set(
        inspector.get_table_names(
            schema="canonical"
        )
    )

    required = {
        "canonical_vulnerability",
        "canonical_vulnerability_identifier",
        "canonical_vulnerability_evidence",
        "canonical_vulnerability_weakness",
    }

    return required.issubset(existing)


def load_canonical_metrics(
    connection: Connection,
    inspector: Inspector,
    warnings: list[str],
) -> CanonicalMetrics | None:
    if not canonical_tables_exist(inspector):
        warnings.append(
            "Les tables canoniques de vulnérabilités "
            "ne sont pas toutes présentes. "
            "Les métriques canoniques sont ignorées."
        )
        return None

    metrics_row = connection.execute(
        text(
            """
            WITH vulnerability_facts AS (
                SELECT
                    vulnerability.id,
                    vulnerability.status,

                    bool_or(
                        identifier.namespace = 'CVE'
                    ) AS has_cve,

                    bool_or(
                        identifier.namespace = 'CVE'
                        AND identifier.is_primary
                    ) AS has_primary_cve,

                    bool_or(
                        identifier.namespace = 'GHSA'
                        AND identifier.is_primary
                    ) AS has_primary_ghsa,

                    EXISTS (
                        SELECT 1
                        FROM canonical
                            .canonical_vulnerability_weakness
                            AS weakness
                        WHERE weakness.vulnerability_id
                              = vulnerability.id
                    ) AS has_cwe,

                    EXISTS (
                        SELECT 1
                        FROM canonical
                            .canonical_vulnerability_evidence
                            AS epss_evidence
                        WHERE epss_evidence.vulnerability_id
                              = vulnerability.id
                          AND lower(
                              epss_evidence.source
                          ) = ANY(:epss_sources)
                    ) AS has_epss,

                    (
                        SELECT COUNT(
                            DISTINCT evidence.source
                        )
                        FROM canonical
                            .canonical_vulnerability_evidence
                            AS evidence
                        WHERE evidence.vulnerability_id
                              = vulnerability.id
                    ) AS source_count

                FROM canonical
                    .canonical_vulnerability
                    AS vulnerability

                LEFT JOIN canonical
                    .canonical_vulnerability_identifier
                    AS identifier
                  ON identifier.vulnerability_id
                     = vulnerability.id

                GROUP BY
                    vulnerability.id,
                    vulnerability.status
            )
            SELECT
                COUNT(*) AS total_canonical,

                COUNT(*) FILTER (
                    WHERE has_cve
                ) AS total_with_cve,

                COUNT(*) FILTER (
                    WHERE NOT has_cve
                ) AS total_without_cve,

                COUNT(*) FILTER (
                    WHERE has_primary_cve
                ) AS primary_cve,

                COUNT(*) FILTER (
                    WHERE has_primary_ghsa
                ) AS primary_ghsa,

                COUNT(*) FILTER (
                    WHERE has_cve
                      AND has_cwe
                ) AS cve_with_cwe,

                COUNT(*) FILTER (
                    WHERE has_cve
                      AND NOT has_cwe
                ) AS cve_without_cwe,

                COUNT(*) FILTER (
                    WHERE has_cve
                      AND has_epss
                ) AS cve_with_epss,

                COUNT(*) FILTER (
                    WHERE has_cve
                      AND NOT has_epss
                ) AS cve_without_epss,

                COUNT(*) FILTER (
                    WHERE has_cve
                      AND (
                          has_cwe
                          OR has_epss
                      )
                ) AS cve_with_any_enrichment,

                COUNT(*) FILTER (
                    WHERE has_cve
                      AND NOT has_cwe
                      AND NOT has_epss
                ) AS cve_without_any_enrichment,

                COUNT(*) FILTER (
                    WHERE has_cve
                      AND source_count > 1
                ) AS multi_source_cve,

                COUNT(*) FILTER (
                    WHERE has_cve
                      AND source_count <= 1
                ) AS single_source_cve

            FROM vulnerability_facts
            """
        ),
        {
            "epss_sources": list(
                EPSS_SOURCE_NAMES
            ),
        },
    ).mappings().one()

    status_rows = connection.execute(
        text(
            """
            SELECT
                status,
                COUNT(*) AS count
            FROM canonical
                .canonical_vulnerability
            GROUP BY status
            ORDER BY status
            """
        )
    ).mappings().all()

    canonical_tables = set(
        inspector.get_table_names(
            schema="canonical"
        )
    )

    web_indicator_count = 0
    web_observation_count = 0

    if (
        "canonical_web_indicator"
        in canonical_tables
    ):
        web_indicator_count = execute_scalar_int(
            connection,
            """
            SELECT COUNT(*)
            FROM canonical.canonical_web_indicator
            """,
        )

    if (
        "canonical_web_indicator_observation"
        in canonical_tables
    ):
        web_observation_count = execute_scalar_int(
            connection,
            """
            SELECT COUNT(*)
            FROM canonical
                .canonical_web_indicator_observation
            """,
        )

    return CanonicalMetrics(
        total_canonical_vulnerabilities=int(
            metrics_row["total_canonical"]
        ),
        canonical_vulnerabilities_by_status={
            str(row["status"]): int(row["count"])
            for row in status_rows
        },
        total_vulnerabilities_with_cve=int(
            metrics_row["total_with_cve"]
        ),
        total_vulnerabilities_without_cve=int(
            metrics_row["total_without_cve"]
        ),
        total_primary_cve_identifiers=int(
            metrics_row["primary_cve"]
        ),
        total_primary_ghsa_identifiers=int(
            metrics_row["primary_ghsa"]
        ),
        cve_with_cwe_enrichment=int(
            metrics_row["cve_with_cwe"]
        ),
        cve_without_cwe_enrichment=int(
            metrics_row["cve_without_cwe"]
        ),
        cve_with_epss_evidence=int(
            metrics_row["cve_with_epss"]
        ),
        cve_without_epss_evidence=int(
            metrics_row["cve_without_epss"]
        ),
        cve_with_any_enrichment=int(
            metrics_row[
                "cve_with_any_enrichment"
            ]
        ),
        cve_without_any_enrichment=int(
            metrics_row[
                "cve_without_any_enrichment"
            ]
        ),
        multi_source_cve=int(
            metrics_row["multi_source_cve"]
        ),
        single_source_cve=int(
            metrics_row["single_source_cve"]
        ),
        total_canonical_web_indicators=(
            web_indicator_count
        ),
        total_web_indicator_observations=(
            web_observation_count
        ),
        enrichment_definition=(
            "Une CVE est considérée enrichie lorsqu'elle "
            "possède au moins une relation CWE canonique "
            "ou une preuve canonique provenant d'EPSS. "
            "Les CVE sans enrichissement restent incluses "
            "dans le total canonique."
        ),
    )


# ============================================================
# Construction du document
# ============================================================

def build_database_documentation(
    connection: Connection,
    managed_schemas: list[str],
    *,
    exact_counts_enabled: bool,
) -> DatabaseDocumentation:
    warnings: list[str] = []

    inspector = inspect(connection)

    validate_database_role(connection)

    (
        database_name,
        database_user,
        server_version,
    ) = load_database_identity(connection)

    schemas = load_schemas(
        connection,
        inspector,
        managed_schemas,
        exact_counts_enabled=exact_counts_enabled,
        warnings=warnings,
    )

    canonical_metrics = load_canonical_metrics(
        connection,
        inspector,
        warnings,
    )

    return DatabaseDocumentation(
        generated_at_utc=datetime.now(
            timezone.utc
        ).isoformat(),
        database_name=database_name,
        database_user=database_user,
        server_version=server_version,
        alembic_version=load_alembic_version(
            connection
        ),
        exact_counts_enabled=(
            exact_counts_enabled
        ),
        schemas=schemas,
        other_objects=load_other_objects(
            connection,
            managed_schemas,
        ),
        canonical_metrics=canonical_metrics,
        warnings=warnings,
    )


# ============================================================
# Génération Markdown
# ============================================================

def append_canonical_metrics_markdown(
    lines: list[str],
    metrics: CanonicalMetrics | None,
) -> None:
    lines.extend(
        [
            "## Vue métier canonique",
            "",
        ]
    )

    if metrics is None:
        lines.extend(
            [
                (
                    "Les métriques canoniques "
                    "ne sont pas disponibles."
                ),
                "",
            ]
        )
        return

    lines.extend(
        [
            (
                "> **Règle de comptage :** "
                "une vulnérabilité canonique est comptée "
                "une seule fois depuis "
                "`canonical.canonical_vulnerability`. "
                "Les identifiants, preuves et CWE ne sont "
                "pas ajoutés au total."
            ),
            "",
            (
                f"- Vulnérabilités canoniques : "
                f"**{metrics.total_canonical_vulnerabilities}**"
            ),
            (
                f"- Vulnérabilités avec CVE : "
                f"**{metrics.total_vulnerabilities_with_cve}**"
            ),
            (
                f"- Vulnérabilités sans CVE : "
                f"**{metrics.total_vulnerabilities_without_cve}**"
            ),
            (
                f"- Identifiant principal CVE : "
                f"**{metrics.total_primary_cve_identifiers}**"
            ),
            (
                f"- Identifiant principal GHSA : "
                f"**{metrics.total_primary_ghsa_identifiers}**"
            ),
            "",
            "### Enrichissement des CVE",
            "",
            (
                f"- CVE avec au moins un CWE : "
                f"**{metrics.cve_with_cwe_enrichment}**"
            ),
            (
                f"- CVE sans CWE : "
                f"**{metrics.cve_without_cwe_enrichment}**"
            ),
            (
                f"- CVE avec preuve EPSS : "
                f"**{metrics.cve_with_epss_evidence}**"
            ),
            (
                f"- CVE sans preuve EPSS : "
                f"**{metrics.cve_without_epss_evidence}**"
            ),
            (
                f"- CVE avec au moins un enrichissement : "
                f"**{metrics.cve_with_any_enrichment}**"
            ),
            (
                f"- CVE sans aucun enrichissement : "
                f"**{metrics.cve_without_any_enrichment}**"
            ),
            "",
            "### Corrélation",
            "",
            (
                f"- CVE multi-sources : "
                f"**{metrics.multi_source_cve}**"
            ),
            (
                f"- CVE mono-source : "
                f"**{metrics.single_source_cve}**"
            ),
            "",
            "### Indicateurs web",
            "",
            (
                f"- Indicateurs web canoniques : "
                f"**{metrics.total_canonical_web_indicators}**"
            ),
            (
                f"- Observations d'indicateurs web : "
                f"**{metrics.total_web_indicator_observations}**"
            ),
            "",
            (
                f"Définition appliquée : "
                f"{metrics.enrichment_definition}"
            ),
            "",
            "### Répartition par statut",
            "",
            "| Statut | Nombre |",
            "|---|---:|",
        ]
    )

    for status, count in (
        metrics
        .canonical_vulnerabilities_by_status
        .items()
    ):
        lines.append(
            f"| {markdown_escape(status)} | {count} |"
        )

    lines.append("")


def append_table_markdown(
    lines: list[str],
    table: TableDocumentation,
) -> None:
    qualified_name = (
        f"{table.schema_name}.{table.table_name}"
    )

    lines.extend(
        [
            f"### `{qualified_name}`",
            "",
        ]
    )

    if table.comment:
        lines.extend(
            [
                markdown_escape(table.comment),
                "",
            ]
        )

    lines.extend(
        [
            "| Information | Valeur |",
            "|---|---|",
            (
                "| Type d'objet | "
                f"{markdown_code(table.object_type)} |"
            ),
            (
                "| Nombre exact de lignes | "
                f"{table.exact_row_count if table.exact_row_count is not None else 'Non calculé'} |"
            ),
            (
                "| Estimation PostgreSQL | "
                f"{table.estimated_row_count if table.estimated_row_count is not None else 'Non disponible'} |"
            ),
            (
                "| Taille totale | "
                f"{format_bytes(table.total_size_bytes)} |"
            ),
            (
                "| Taille des données | "
                f"{format_bytes(table.table_size_bytes)} |"
            ),
            (
                "| Taille des index | "
                f"{format_bytes(table.indexes_size_bytes)} |"
            ),
            "",
            "#### Colonnes",
            "",
            (
                "| Colonne | Type | Nullable | "
                "Valeur par défaut | Auto-incrément | Commentaire |"
            ),
            (
                "|---|---|:---:|---|---|---|"
            ),
        ]
    )

    for column in table.columns:
        lines.append(
            "| "
            f"{markdown_code(column.name)} | "
            f"{markdown_code(column.data_type)} | "
            f"{'Oui' if column.nullable else 'Non'} | "
            f"{markdown_code(column.default)} | "
            f"{markdown_code(column.autoincrement)} | "
            f"{markdown_escape(column.comment) or '—'} |"
        )

    lines.extend(
        [
            "",
            "#### Contraintes",
            "",
        ]
    )

    if not table.constraints:
        lines.extend(
            [
                "Aucune contrainte déclarée.",
                "",
            ]
        )
    else:
        lines.extend(
            [
                "| Nom | Type | Définition |",
                "|---|---|---|",
            ]
        )

        for constraint in table.constraints:
            lines.append(
                "| "
                f"{markdown_code(constraint.name)} | "
                f"{markdown_escape(constraint.constraint_type)} | "
                f"{markdown_code(constraint.definition)} |"
            )

        lines.append("")

    lines.extend(
        [
            "#### Index",
            "",
        ]
    )

    if not table.indexes:
        lines.extend(
            [
                "Aucun index.",
                "",
            ]
        )
    else:
        lines.extend(
            [
                (
                    "| Nom | Unique | Primaire | "
                    "Valide | Définition |"
                ),
                "|---|:---:|:---:|:---:|---|",
            ]
        )

        for index in table.indexes:
            lines.append(
                "| "
                f"{markdown_code(index.name)} | "
                f"{'Oui' if index.unique else 'Non'} | "
                f"{'Oui' if index.primary else 'Non'} | "
                f"{'Oui' if index.valid else 'Non'} | "
                f"{markdown_code(index.definition)} |"
            )

        lines.append("")

    lines.extend(
        [
            "#### Triggers",
            "",
        ]
    )

    if not table.triggers:
        lines.extend(
            [
                "Aucun trigger utilisateur.",
                "",
            ]
        )
    else:
        lines.extend(
            [
                "| Nom | État | Définition |",
                "|---|---|---|",
            ]
        )

        for trigger in table.triggers:
            lines.append(
                "| "
                f"{markdown_code(trigger.name)} | "
                f"{markdown_escape(trigger.enabled)} | "
                f"{markdown_code(trigger.definition)} |"
            )

        lines.append("")


def render_markdown(
    documentation: DatabaseDocumentation,
) -> str:
    lines: list[str] = [
        "# Documentation PostgreSQL",
        "",
        (
            "> Document généré automatiquement. "
            "Ne pas modifier manuellement."
        ),
        "",
        "## Informations générales",
        "",
        "| Information | Valeur |",
        "|---|---|",
        (
            "| Généré le | "
            f"`{documentation.generated_at_utc}` |"
        ),
        (
            "| Base de données | "
            f"`{documentation.database_name}` |"
        ),
        (
            "| Utilisateur de lecture | "
            f"`{documentation.database_user}` |"
        ),
        (
            "| Version PostgreSQL | "
            f"`{documentation.server_version}` |"
        ),
        (
            "| Version Alembic | "
            f"{markdown_code(documentation.alembic_version)} |"
        ),
        (
            "| Comptages exacts | "
            f"{'Oui' if documentation.exact_counts_enabled else 'Non'} |"
        ),
        "",
    ]

    append_canonical_metrics_markdown(
        lines,
        documentation.canonical_metrics,
    )

    lines.extend(
        [
            "## Navigation",
            "",
        ]
    )

    for schema in documentation.schemas:
        lines.append(
            f"- [{schema.name}]"
            f"(#{markdown_anchor(f'schema-{schema.name}')})"
        )

        for table in schema.tables:
            qualified_name = (
                f"{schema.name}.{table.table_name}"
            )

            lines.append(
                f"  - [{qualified_name}]"
                f"(#{markdown_anchor(qualified_name)})"
            )

    lines.append("")

    lines.extend(
        [
            "## Résumé des schémas",
            "",
            "| Schéma | Owner | Tables | Lignes exactes |",
            "|---|---|---:|---:|",
        ]
    )

    for schema in documentation.schemas:
        exact_total = sum(
            table.exact_row_count or 0
            for table in schema.tables
        )

        exact_display = (
            str(exact_total)
            if documentation.exact_counts_enabled
            else "Non calculé"
        )

        lines.append(
            "| "
            f"{markdown_code(schema.name)} | "
            f"{markdown_code(schema.owner)} | "
            f"{len(schema.tables)} | "
            f"{exact_display} |"
        )

    lines.append("")

    for schema in documentation.schemas:
        lines.extend(
            [
                (
                    f"## Schéma `{schema.name}`"
                    f" {{#schema-{schema.name}}}"
                ),
                "",
                (
                    f"- Owner : "
                    f"{markdown_code(schema.owner)}"
                ),
                (
                    f"- Nombre de tables : "
                    f"**{len(schema.tables)}**"
                ),
                "",
            ]
        )

        if schema.comment:
            lines.extend(
                [
                    markdown_escape(schema.comment),
                    "",
                ]
            )

        for table in schema.tables:
            append_table_markdown(
                lines,
                table,
            )

    lines.extend(
        [
            "## Autres objets PostgreSQL",
            "",
        ]
    )

    if not documentation.other_objects:
        lines.extend(
            [
                (
                    "Aucune vue, vue matérialisée, "
                    "séquence, fonction, procédure "
                    "ou enum métier détecté."
                ),
                "",
            ]
        )
    else:
        lines.extend(
            [
                (
                    "| Schéma | Objet | Type | "
                    "Owner | Définition |"
                ),
                "|---|---|---|---|---|",
            ]
        )

        for database_object in (
            documentation.other_objects
        ):
            lines.append(
                "| "
                f"{markdown_code(database_object.schema_name)} | "
                f"{markdown_code(database_object.object_name)} | "
                f"{markdown_escape(database_object.object_type)} | "
                f"{markdown_code(database_object.owner)} | "
                f"{markdown_code(database_object.definition)} |"
            )

        lines.append("")

    if documentation.warnings:
        lines.extend(
            [
                "## Avertissements",
                "",
            ]
        )

        for warning in documentation.warnings:
            lines.append(
                f"- {markdown_escape(warning)}"
            )

        lines.append("")

    lines.extend(
        [
            "## Notes de sécurité",
            "",
            (
                "- Le document contient uniquement la structure "
                "et les statistiques de la base."
            ),
            (
                "- Aucun payload JSON brut n'est extrait."
            ),
            (
                "- Aucun token, mot de passe ou URL de connexion "
                "n'est écrit dans les fichiers."
            ),
            (
                "- Les valeurs de `raw.source_payload.payload` "
                "ne sont jamais lues."
            ),
            "",
        ]
    )

    return "\n".join(lines)


# ============================================================
# Écriture atomique
# ============================================================

def write_text_atomically(
    path: Path,
    content: str,
) -> None:
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    temporary_path = path.with_suffix(
        f"{path.suffix}.tmp"
    )

    temporary_path.write_text(
        content,
        encoding="utf-8",
        newline="\n",
    )

    temporary_path.replace(path)


def write_documentation_files(
    documentation: DatabaseDocumentation,
    output_directory: Path,
) -> tuple[Path, Path]:
    output_directory = output_directory.resolve()

    markdown_path = (
        output_directory
        / MARKDOWN_FILE_NAME
    )

    json_path = (
        output_directory
        / JSON_FILE_NAME
    )

    markdown_content = render_markdown(
        documentation
    )

    json_content = json.dumps(
        asdict(documentation),
        ensure_ascii=False,
        indent=2,
        sort_keys=False,
    )

    write_text_atomically(
        markdown_path,
        markdown_content,
    )

    write_text_atomically(
        json_path,
        f"{json_content}\n",
    )

    return markdown_path, json_path


# ============================================================
# Point d'entrée
# ============================================================

def main() -> int:
    arguments = parse_arguments()

    try:
        managed_schemas = validate_schema_names(
            list(arguments.schemas)
        )

        database_url = get_database_url()

        engine = create_database_engine(
            database_url
        )

        try:
            with engine.connect() as connection:
                transaction = connection.begin()

                try:
                    # La génération de documentation ne doit
                    # effectuer aucune écriture.
                    connection.execute(
                        text(
                            """
                            SET TRANSACTION
                            READ ONLY
                            """
                        )
                    )

                    # Évite qu'une requête documentaire reste
                    # bloquée indéfiniment.
                    connection.execute(
                        text(
                            """
                            SET LOCAL
                            statement_timeout = '60s'
                            """
                        )
                    )

                    connection.execute(
                        text(
                            """
                            SET LOCAL
                            lock_timeout = '5s'
                            """
                        )
                    )

                    documentation = (
                        build_database_documentation(
                            connection,
                            managed_schemas,
                            exact_counts_enabled=(
                                not arguments
                                .estimated_counts_only
                            ),
                        )
                    )

                    transaction.commit()

                except Exception:
                    transaction.rollback()
                    raise

        finally:
            engine.dispose()

        markdown_path, json_path = (
            write_documentation_files(
                documentation,
                arguments.output_directory,
            )
        )

        print(
            "Documentation PostgreSQL générée :"
        )
        print(
            f"- Markdown : {markdown_path}"
        )
        print(
            f"- JSON     : {json_path}"
        )

        return 0

    except (
        RuntimeError,
        ValueError,
        SQLAlchemyError,
        OSError,
    ) as error:
        print(
            "Échec de la génération de la "
            "documentation PostgreSQL : "
            f"{error}",
            file=sys.stderr,
        )

        return 1


if __name__ == "__main__":
    raise SystemExit(main())