"""Migration state helpers used by readiness and tests."""

from pathlib import Path

from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory

from persistence.database import Database
from config.settings import Settings


def expected_revision(project_root: Path) -> str:
    config = Config(str(project_root / "alembic.ini"))
    return ScriptDirectory.from_config(config).get_current_head()


def migrations_current(database: Database, project_root: Path) -> bool:
    return database.current_revision() == expected_revision(project_root)


def apply_migrations(settings: Settings) -> None:
    config = Config(str(settings.project_root / "alembic.ini"))
    config.attributes["settings"] = settings
    command.upgrade(config, "head")
