from sqlalchemy import text

from infrastructure.persistence.sqlalchemy import (
    create_ingestion_engine,
    create_session_factory,
)


def test_ingestion_database_connection() -> None:
    engine = create_ingestion_engine()
    session_factory = create_session_factory(engine)

    with session_factory() as session:
        result = session.execute(
            text(
                """
                SELECT
                    current_user,
                    has_schema_privilege(
                        current_user,
                        'ops',
                        'USAGE'
                    )
                """
            )
        ).one()

    assert result.current_user == "threat_intel_ingestion"
    assert result.has_schema_privilege is True