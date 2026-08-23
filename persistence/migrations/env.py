"""Alembic environment bound to WireScope configuration."""

from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

from config.settings import get_settings
from persistence.models import Base


config = context.config
if config.config_file_name:
    fileConfig(config.config_file_name)

settings = config.attributes.get("settings") or get_settings()
settings.database_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
config.set_main_option(
    "sqlalchemy.url",
    settings.database_url.replace("%", "%%"),
)
target_metadata = Base.metadata


def run_migrations_offline() -> None:
    context.configure(
        url=config.get_main_option("sqlalchemy.url"),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
        connect_args={
            "timeout": settings.sqlite_busy_timeout_ms / 1_000,
        },
    )
    with connectable.connect() as connection:
        connection.exec_driver_sql("PRAGMA foreign_keys=ON")
        connection.exec_driver_sql(
            f"PRAGMA busy_timeout={settings.sqlite_busy_timeout_ms}"
        )
        connection.commit()
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
