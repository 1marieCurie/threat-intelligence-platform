from __future__ import annotations

from fastapi import FastAPI

from application.services.import_machine_inventory_service import (
    ImportMachineInventoryService,
)
from infrastructure.api.app import (
    create_app,
)
from infrastructure.api.machine_credentials import (
    load_machine_api_key_authenticator,
)
from infrastructure.persistence.sqlalchemy.asset_engine import (
    create_asset_engine,
)
from infrastructure.persistence.sqlalchemy.asset_inventory_unit_of_work import (
    SqlAlchemyAssetInventoryUnitOfWork,
)
from infrastructure.persistence.sqlalchemy.session import (
    create_session_factory,
)


def build_app() -> FastAPI:
    engine = create_asset_engine()

    session_factory = (
        create_session_factory(
            engine
        )
    )

    unit_of_work = (
        SqlAlchemyAssetInventoryUnitOfWork(
            session_factory
        )
    )

    import_service = (
        ImportMachineInventoryService(
            unit_of_work=unit_of_work
        )
    )

    authenticator = (
        load_machine_api_key_authenticator()
    )

    app = create_app(
        import_service=import_service,
        authenticator=authenticator,
    )

    # Conserver une référence explicite durant
    # toute la durée de vie du processus.
    app.state.asset_engine = engine

    return app


app = build_app()