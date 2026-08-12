from __future__ import annotations

import os
from collections.abc import MutableMapping
from logging.config import fileConfig
from pathlib import Path
from typing import Literal, TypeAlias

from dotenv import load_dotenv


PROJECT_ROOT = (
    Path(__file__)
    .resolve()
    .parents[1]
)

ENV_FILE = (
    PROJECT_ROOT
    / ".env"
)

load_dotenv(
    dotenv_path=ENV_FILE,
    override=False,
)


from alembic import context
from sqlalchemy import (
    engine_from_config,
    pool,
    text,
)

from infrastructure.persistence.models import (
    Base,
)


# ============================================================
# Types du callback include_name
# ============================================================

ObjectType: TypeAlias = Literal[
    "schema",
    "table",
    "column",
    "index",
    "unique_constraint",
    "foreign_key_constraint",
]

ParentNameKey: TypeAlias = Literal[
    "schema_name",
    "table_name",
    "schema_qualified_table_name",
]

ParentNames: TypeAlias = MutableMapping[
    ParentNameKey,
    str | None,
]


# ============================================================
# Configuration générale d'Alembic
# ============================================================

config = context.config

if config.config_file_name is not None:
    fileConfig(
        config.config_file_name
    )


migration_database_url = os.environ.get(
    "MIGRATION_DATABASE_URL"
)

if not migration_database_url:
    raise RuntimeError(
        "MIGRATION_DATABASE_URL is not defined"
    )

config.set_main_option(
    "sqlalchemy.url",
    migration_database_url,
)


target_metadata = (
    Base.metadata
)


# ============================================================
# Schémas gérés par le projet
# ============================================================

MANAGED_SCHEMAS: set[str] = {
    "threat_intel",
    "ops",
    "raw",
    "normalized",
    "canonical",
    "ml",
}


def include_name(
    name: str | None,
    type_: ObjectType,
    parent_names: ParentNames,
) -> bool:
    """
    Limite l'inspection Alembic aux schémas
    explicitement gérés par la plateforme.
    """

    del parent_names

    if type_ == "schema":
        return (
            name
            in MANAGED_SCHEMAS
        )

    return True


# ============================================================
# Mode hors ligne
# ============================================================

def run_migrations_offline() -> None:
    """
    Génère le SQL sans ouvrir de connexion PostgreSQL.

    Exemple :
        python -m alembic upgrade head --sql
    """

    url = config.get_main_option(
        "sqlalchemy.url"
    )

    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={
            "paramstyle": "named",
        },
        include_schemas=True,
        include_name=include_name,
        version_table="alembic_version",
        version_table_schema="threat_intel",
        compare_type=True,
        compare_server_default=True,
    )

    with context.begin_transaction():
        context.execute(
            "SET ROLE threat_intel_owner"
        )

        context.run_migrations()

        context.execute(
            "RESET ROLE"
        )


# ============================================================
# Mode en ligne
# ============================================================

def run_migrations_online() -> None:
    """
    Exécute réellement les migrations PostgreSQL.

    La connexion est ouverte avec le rôle migrator,
    puis les opérations sont exécutées comme
    threat_intel_owner.
    """

    configuration = config.get_section(
        config.config_ini_section,
        {},
    )

    connectable = engine_from_config(
        configuration,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        connection.execute(
            text(
                "SET ROLE threat_intel_owner"
            )
        )

        # Le premier execute() ouvre une transaction
        # implicite avec SQLAlchemy.
        connection.commit()

        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            include_schemas=True,
            include_name=include_name,
            version_table="alembic_version",
            version_table_schema="threat_intel",
            compare_type=True,
            compare_server_default=True,
        )

        try:
            with context.begin_transaction():
                context.run_migrations()

        finally:
            connection.execute(
                text(
                    "RESET ROLE"
                )
            )

            connection.commit()


# ============================================================
# Point d'entrée
# ============================================================

if context.is_offline_mode():
    run_migrations_offline()

else:
    run_migrations_online()