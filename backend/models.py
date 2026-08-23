"""Versioned HTTP contracts for passive discovery."""

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field, model_validator

from config.settings import get_settings
from engine.interfaces import InterfaceInfo
from engine.passive_models import PassiveResult


class PassiveStartRequest(BaseModel):
    interface: str = Field(min_length=1, max_length=64)
    duration_seconds: int | None = None

    @model_validator(mode="after")
    def validate_duration(self) -> "PassiveStartRequest":
        settings = get_settings()
        if self.duration_seconds is None:
            self.duration_seconds = settings.passive_duration_default
        if not (
            settings.passive_duration_min
            <= self.duration_seconds
            <= settings.passive_duration_max
        ):
            raise ValueError(
                "duration_seconds must be between "
                f"{settings.passive_duration_min} and "
                f"{settings.passive_duration_max}"
            )
        return self


class PassiveStartResponse(BaseModel):
    job_id: str
    status: str


class JobStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class JobResponse(BaseModel):
    id: str
    type: str
    target: str
    status: JobStatus
    created_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None
    progress: int = Field(ge=0, le=100)
    result: PassiveResult | None = None
    error: str | None = None


class InterfaceListResponse(BaseModel):
    interfaces: list[InterfaceInfo]
