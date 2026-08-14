from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv
from sqlalchemy import Engine, create_engine


PROJECT_ROOT = Path(
    __file__
).resolve().parents[3]

ENV_FILE = PROJECT_ROOT / ".env"

load_dotenv(
    dotenv_path=ENV_FILE,
    override=False,
)


def create_asset_engine() -> Engine:
    database_url = os.environ.get(
        "ASSET_DATABASE_URL"
    )

    if not database_url:
        raise RuntimeError(
            "ASSET_DATABASE_URL is not defined"
        )

    return create_engine(
        database_url,
        pool_pre_ping=True,
        pool_recycle=1800,
        future=True,
    )