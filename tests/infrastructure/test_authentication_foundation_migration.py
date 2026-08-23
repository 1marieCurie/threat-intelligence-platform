from __future__ import annotations

from alembic.config import Config
from alembic.script import ScriptDirectory


AUTH_FOUNDATION_REVISION = (
    "86d4692edc3c"
)

AUTH_TENANT_IDENTITY_REVISION = (
    "a91e7c4d2f10"
)


def test_authentication_tenant_identity_is_current_head(
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
        == AUTH_TENANT_IDENTITY_REVISION
    )


def test_authentication_foundation_extends_asset_core(
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
            AUTH_FOUNDATION_REVISION
        )
    )

    assert revision is not None

    assert (
        revision.down_revision
        == "d2f1a6b7c9e0"
    )


def test_authentication_tenant_identity_extends_foundation(
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
            AUTH_TENANT_IDENTITY_REVISION
        )
    )

    assert revision is not None

    assert (
        revision.down_revision
        == AUTH_FOUNDATION_REVISION
    )