from __future__ import annotations
from dotenv import load_dotenv

import os
from pathlib import Path

from sqlalchemy import Engine, create_engine


PROJECT_ROOT = Path(__file__).resolve().parents[3]
ENV_FILE = PROJECT_ROOT / ".env"

load_dotenv(
    dotenv_path=ENV_FILE,
    override=False,
)


def create_ingestion_engine() -> Engine:
    database_url = os.environ.get("INGESTION_DATABASE_URL")

    if not database_url:
        raise RuntimeError(
            "INGESTION_DATABASE_URL is not defined"
        )

    return create_engine(
        database_url,
        pool_pre_ping=True,
        pool_recycle=1800,
        future=True,
    )