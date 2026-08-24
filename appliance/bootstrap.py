"""Create the first local operators from password files, never from unit files."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import secrets
import stat
from typing import TYPE_CHECKING

from appliance.host import Host

if TYPE_CHECKING:
    from config.settings import Settings
    from persistence.database import Database


class BootstrapError(ValueError):
    pass


@dataclass(frozen=True)
class PasswordFile:
    path: Path
    password: str


def read_password_file(path: Path, *, require_strict_mode: bool = True) -> PasswordFile:
    if not path.is_file():
        raise BootstrapError(f"password file not found: {path}")
    mode = stat.S_IMODE(path.stat().st_mode)
    if require_strict_mode and mode & 0o077:
        raise BootstrapError(
            f"password file {path} must be mode 0600 or stricter (got {mode:04o})"
        )
    password = path.read_text(encoding="utf-8").replace("\r", "").strip("\n")
    if not password:
        raise BootstrapError("password file is empty")
    if len(password) < 8:
        raise BootstrapError("password must be at least 8 characters")
    return PasswordFile(path=path, password=password)


def password_from_host(host: Host, path: Path) -> str:
    if not host.is_file(path):
        raise BootstrapError(f"password file not found: {path}")
    mode = host.file_mode(path)
    if mode & 0o077:
        raise BootstrapError(
            f"password file {path} must be mode 0600 or stricter (got {mode:04o})"
        )
    password = host.read_text(path).replace("\r", "").strip("\n")
    if not password:
        raise BootstrapError("password file is empty")
    if len(password) < 8:
        raise BootstrapError("password must be at least 8 characters")
    return password


def write_password_file(path: Path, password: str) -> Path:
    if len(password) < 8:
        raise BootstrapError("password must be at least 8 characters")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.write_text(password + "\n", encoding="utf-8")
    path.chmod(0o600)
    return path


def _has_users(database: Database) -> bool:
    from sqlalchemy import inspect, select

    from persistence.models import UserModel

    inspector = inspect(database.engine)
    if "users" not in inspector.get_table_names():
        return False
    with database.session() as session:
        return session.scalar(select(UserModel.id).limit(1)) is not None


def create_initial_operators(
    settings: Settings,
    *,
    auditor_username: str,
    auditor_password: str,
    viewer_username: str = "",
    viewer_password: str = "",
    database: Database | None = None,
) -> list[str]:
    from auth.models import Role
    from auth.service import AuthError, AuthService
    from persistence.database import Database
    from persistence.schema import apply_migrations

    apply_migrations(settings)
    active = database or Database(settings)
    try:
        if _has_users(active):
            return []
        service = AuthService(active, settings)
        created: list[str] = []
        if not auditor_username or not auditor_password:
            raise BootstrapError("initial auditor username and password are required")
        try:
            user = service.create_user(
                username=auditor_username,
                password=auditor_password,
                role=Role.AUDITOR,
            )
            created.append(user.username)
        except AuthError as exc:
            raise BootstrapError(exc.message) from exc
        if viewer_username and viewer_password:
            try:
                user = service.create_user(
                    username=viewer_username,
                    password=viewer_password,
                    role=Role.VIEWER,
                )
                created.append(user.username)
            except AuthError as exc:
                raise BootstrapError(exc.message) from exc
        return created
    finally:
        if database is None:
            active.dispose()


def default_password_output(settings: Settings, username: str) -> Path:
    name = "initial-admin.txt" if username.strip() == "auditor" else f"{username.strip()}.txt"
    return settings.data_dir / name


def set_operator_password(
    settings: Settings,
    *,
    username: str,
    password: str | None = None,
    output: Path | None = None,
    database: Database | None = None,
) -> Path:
    """Reset a local operator password and write a mode 0600 file. Never prints the secret."""

    from auth.service import AuthError, AuthService
    from persistence.database import Database

    if output is None:
        output = default_password_output(settings, username)
    if password is None:
        password = secrets.token_urlsafe(24)
    active = database or Database(settings)
    try:
        service = AuthService(active, settings)
        try:
            service.set_password(username=username, password=password)
        except AuthError as exc:
            raise BootstrapError(exc.message) from exc
        return write_password_file(output, password)
    finally:
        if database is None:
            active.dispose()
