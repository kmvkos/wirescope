"""Local operator authentication and role-aware sessions."""

from auth.models import Role, SessionUser
from auth.service import AuthError, AuthService

__all__ = ["AuthError", "AuthService", "Role", "SessionUser"]
