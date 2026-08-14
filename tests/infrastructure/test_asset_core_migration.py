from __future__ import annotations

from alembic.config import Config
from alembic.script import ScriptDirectory


def test_asset_core_migration_is_current_head() -> None:
    config = Config("alembic.ini")
    script = ScriptDirectory.from_config(config)

    assert script.get_current_head() == "d2f1a6b7c9e0"


def test_asset_core_migration_extends_previous_head() -> None:
    config = Config("alembic.ini")
    script = ScriptDirectory.from_config(config)

    revision = script.get_revision(
        "d2f1a6b7c9e0"
    )

    assert revision is not None
    assert revision.down_revision == "9a71c3e5d2f4"