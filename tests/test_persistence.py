from dataclasses import replace

from sqlalchemy import inspect, text

from persistence.database import Database
from persistence.schema import (
    apply_migrations,
    expected_revision,
    migrations_current,
)


def test_migrations_build_working_schema_from_empty_database(
    durable_settings,
    tmp_path,
):
    settings = replace(
        durable_settings,
        database_path=tmp_path / "empty" / "wirescope.db",
    )

    apply_migrations(settings)
    database = Database(settings)
    try:
        tables = set(inspect(database.engine).get_table_names())
        assert {
            "alembic_version",
            "artifacts",
            "asset_addresses",
            "asset_names",
            "asset_observations",
            "assets",
            "audits",
            "confirmed_scopes",
            "job_events",
            "jobs",
            "resource_locks",
            "services",
            "protocol_observations",
            "findings",
            "finding_state_events",
            "reports",
            "workers",
        } <= tables
        assert migrations_current(database, settings.project_root)
        assert (
            database.current_revision()
            == expected_revision(settings.project_root)
        )
    finally:
        database.dispose()


def test_sqlite_connections_enable_wal_foreign_keys_and_busy_timeout(
    database,
    durable_settings,
):
    with database.engine.connect() as connection:
        assert connection.execute(text("PRAGMA journal_mode")).scalar() == "wal"
        assert connection.execute(text("PRAGMA foreign_keys")).scalar() == 1
        assert (
            connection.execute(text("PRAGMA busy_timeout")).scalar()
            == durable_settings.sqlite_busy_timeout_ms
        )
        assert connection.execute(text("PRAGMA synchronous")).scalar() == 2
