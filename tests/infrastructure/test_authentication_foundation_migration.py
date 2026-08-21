from __future__ import annotations

from alembic.config import Config
from alembic.script import ScriptDirectory


AUTH_REVISION = (
    "86d4692edc3c"
)


def test_authentication_migration_is_current_head(
) -> None:
    config = Config(
        "alembic.ini"
    )

    script = (
        ScriptDirectory.from_config(
            config
        )
    )

    assert (
        script.get_current_head()
        == AUTH_REVISION
    )


def test_authentication_migration_extends_asset_core(
) -> None:
    config = Config(
        "alembic.ini"
    )

    script = (
        ScriptDirectory.from_config(
            config
        )
    )

    revision = (
        script.get_revision(
            AUTH_REVISION
        )
    )

    assert revision is not None

    assert (
        revision.down_revision
        == "d2f1a6b7c9e0"
    )