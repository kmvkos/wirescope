"""Typed contracts for local operator identity."""

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field


class Role(str, Enum):
    AUDITOR = "auditor"
    VIEWER = "viewer"


class SessionUser(BaseModel):
    id: str
    username: str
    role: Role
    created_at: datetime

    @property
    def can_mutate(self) -> bool:
        return self.role is Role.AUDITOR


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=128)


class SessionUserResponse(BaseModel):
    username: str
    role: Role
    capabilities: list[str]
    policy: dict[str, int]


class LoginResponse(SessionUserResponse):
    pass
