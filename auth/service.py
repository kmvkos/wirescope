"""Create local users, issue sessions, and resolve operator cookies."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import re
import uuid

from sqlalchemy import delete, inspect, select
from sqlalchemy.exc import IntegrityError, OperationalError

from auth.models import Role, SessionUser
from auth.passwords import (
    dummy_hash,
    hash_password,
    new_session_token,
    token_digest,
    verify_password,
)
from config.settings import Settings
from persistence.database import Database
from persistence.models import SessionModel, UserModel, utc_now

USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{1,62}[A-Za-z0-9]$")
MIN_PASSWORD_LENGTH = 8
_DUMMY_HASH = dummy_hash()


class AuthError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class AuthService:
    def __init__(self, database: Database, settings: Settings) -> None:
        self.database = database
        self.settings = settings
        self._dummy_hash = _DUMMY_HASH

    def bootstrap(self) -> list[SessionUser]:
        created: list[SessionUser] = []
        inspector = inspect(self.database.engine)
        if "users" not in inspector.get_table_names():
            return created
        try:
            with self.database.session() as session:
                existing = session.scalar(select(UserModel.id).limit(1))
        except OperationalError:
            return created
        if existing is not None:
            return created
        pairs = (
            (
                self.settings.bootstrap_auditor_username,
                self.settings.bootstrap_auditor_password,
                Role.AUDITOR,
            ),
            (
                self.settings.bootstrap_viewer_username,
                self.settings.bootstrap_viewer_password,
                Role.VIEWER,
            ),
        )
        for username, password, role in pairs:
            if not username and not password:
                continue
            created.append(
                self.create_user(
                    username=username,
                    password=password,
                    role=role,
                )
            )
        return created

    def create_user(
        self,
        *,
        username: str,
        password: str,
        role: Role,
    ) -> SessionUser:
        normalized = _normalize_username(username)
        if not USERNAME_PATTERN.fullmatch(normalized):
            raise AuthError(
                "invalid_username",
                "Username must be 3-64 URL-safe characters",
            )
        if len(password) < MIN_PASSWORD_LENGTH:
            raise AuthError(
                "invalid_password",
                f"Password must be at least {MIN_PASSWORD_LENGTH} characters",
            )
        user = UserModel(
            id=str(uuid.uuid4()),
            username=normalized,
            password_hash=hash_password(password),
            role=role.value,
        )
        try:
            with self.database.session() as session, session.begin():
                session.add(user)
        except IntegrityError as exc:
            raise AuthError(
                "username_taken",
                f"Username already exists: {normalized}",
            ) from exc
        return _user_record(user)

    def authenticate(self, username: str, password: str) -> SessionUser:
        normalized = username.strip()
        with self.database.session() as session:
            model = session.scalar(
                select(UserModel).where(UserModel.username == normalized)
            )
            stored = model.password_hash if model is not None else self._dummy_hash
            valid = verify_password(password, stored)
            if model is None or not valid or model.disabled:
                raise AuthError(
                    "invalid_credentials",
                    "Invalid username or password",
                )
            return _user_record(model)

    def create_session(self, user: SessionUser) -> str:
        token = new_session_token()
        expires = utc_now() + timedelta(
            seconds=self.settings.session_ttl_seconds
        )
        with self.database.session() as session, session.begin():
            session.add(
                SessionModel(
                    id=token_digest(token),
                    user_id=user.id,
                    expires_at=expires,
                )
            )
        return token

    def resolve_token(self, token: str | None) -> SessionUser | None:
        if not token:
            return None
        digest = token_digest(token)
        now = utc_now()
        with self.database.session() as session, session.begin():
            model = session.get(SessionModel, digest)
            if model is None:
                return None
            if _aware(model.expires_at) <= now:
                session.delete(model)
                return None
            user = session.get(UserModel, model.user_id)
            if user is None or user.disabled:
                session.delete(model)
                return None
            model.last_seen_at = now
            return _user_record(user)

    def revoke_token(self, token: str | None) -> None:
        if not token:
            return
        digest = token_digest(token)
        with self.database.session() as session, session.begin():
            session.execute(
                delete(SessionModel).where(SessionModel.id == digest)
            )

    def purge_expired(self) -> int:
        now = utc_now()
        with self.database.session() as session, session.begin():
            result = session.execute(
                delete(SessionModel).where(SessionModel.expires_at <= now)
            )
        return int(result.rowcount or 0)


def _normalize_username(username: str) -> str:
    return username.strip()


def _user_record(model: UserModel) -> SessionUser:
    return SessionUser(
        id=model.id,
        username=model.username,
        role=Role(model.role),
        created_at=_aware(model.created_at),
    )


def _aware(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value
