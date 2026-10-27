from datetime import datetime, timezone
from enum import StrEnum
from ipaddress import ip_address
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator


class EventType(StrEnum):
    LOGIN = "login"
    RESOURCE_ACCESS = "resource_access"


class EventOutcome(StrEnum):
    SUCCESS = "success"
    FAILURE = "failure"
    DENIED = "denied"


class SecurityEvent(BaseModel):
    """Canonical event contract shared by producers and consumers."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    event_id: UUID
    timestamp: datetime
    event_type: EventType
    outcome: EventOutcome
    source_ip: str
    user_id: str = Field(min_length=1, max_length=128)
    resource: str | None = Field(default=None, max_length=512)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("timestamp")
    @classmethod
    def normalize_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timestamp must include a timezone")
        return value.astimezone(timezone.utc)

    @field_validator("source_ip")
    @classmethod
    def validate_source_ip(cls, value: str) -> str:
        return str(ip_address(value))

    @field_validator("metadata")
    @classmethod
    def validate_metadata_size(cls, value: dict[str, Any]) -> dict[str, Any]:
        # Prevent arbitrarily large metadata payloads.
        import json

        encoded = json.dumps(value, separators=(",", ":"))
        if len(encoded.encode("utf-8")) > 4096:
            raise ValueError("metadata must not exceed 4096 bytes")
        return value


class AlertSeverity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertStatus(StrEnum):
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"


class SummaryStatus(StrEnum):
    PENDING = "pending"
    COMPLETE = "complete"
    FAILED = "failed"
    NOT_REQUIRED = "not_required"


class SecurityAlert(BaseModel):
    """Canonical alert contract returned by the detection engine."""

    model_config = ConfigDict(extra="forbid")

    alert_id: UUID
    rule_id: str = Field(min_length=1, max_length=100)
    severity: AlertSeverity
    risk_score: int = Field(ge=0, le=100)
    source_ip: str
    event_count: int = Field(ge=1)
    first_seen: datetime
    last_seen: datetime
    status: AlertStatus = AlertStatus.OPEN
    summary_status: SummaryStatus = SummaryStatus.PENDING
    summary: str | None = None
    evidence: dict[str, Any] = Field(default_factory=dict)

    @field_validator("source_ip")
    @classmethod
    def validate_source_ip(cls, value: str) -> str:
        return str(ip_address(value))

    @field_validator("first_seen", "last_seen")
    @classmethod
    def normalize_alert_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("alert timestamps must include a timezone")
        return value.astimezone(timezone.utc)
