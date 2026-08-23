"""SQLAlchemy engine and short-lived session management."""

from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from sqlalchemy import Engine, create_engine, event, text
from sqlalchemy.orm import Session, sessionmaker

from config.settings import Settings, get_settings


class Database:
    """Own the SQLite engine without owning application task lifetime."""

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        self._prepare_parent(self.settings.database_path)
        self.engine = create_engine(
            self.settings.database_url,
            connect_args={
                "check_same_thread": False,
                "timeout": self.settings.sqlite_busy_timeout_ms / 1_000,
            },
            pool_pre_ping=True,
        )
        self._configure_sqlite(self.engine)
        self.session_factory = sessionmaker(
            bind=self.engine,
            class_=Session,
            expire_on_commit=False,
        )

    @contextmanager
    def session(self) -> Iterator[Session]:
        session = self.session_factory()
        try:
            yield session
        finally:
            session.close()

    @contextmanager
    def immediate_session(self) -> Iterator[Session]:
        """Serialize a short claim/recovery transaction with BEGIN IMMEDIATE."""
        connection = self.engine.connect()
        connection.exec_driver_sql("BEGIN IMMEDIATE")
        session = Session(
            bind=connection,
            expire_on_commit=False,
        )
        try:
            yield session
            session.flush()
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            session.close()
            connection.close()

    def is_accessible(self) -> bool:
        try:
            with self.engine.connect() as connection:
                connection.execute(text("SELECT 1"))
            return True
        except Exception:
            return False

    def current_revision(self) -> str | None:
        try:
            with self.engine.connect() as connection:
                return connection.execute(
                    text("SELECT version_num FROM alembic_version")
                ).scalar_one_or_none()
        except Exception:
            return None

    def dispose(self) -> None:
        self.engine.dispose()

    def _configure_sqlite(self, engine: Engine) -> None:
        busy_timeout = self.settings.sqlite_busy_timeout_ms

        @event.listens_for(engine, "connect")
        def set_sqlite_pragmas(dbapi_connection, _connection_record) -> None:
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.execute(f"PRAGMA busy_timeout={busy_timeout}")
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA synchronous=NORMAL")
            cursor.close()

    @staticmethod
    def _prepare_parent(path: Path) -> None:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
