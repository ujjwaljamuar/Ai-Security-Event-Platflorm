from datetime import datetime, timezone
from uuid import uuid4

import pytest
from pydantic import ValidationError

from app.common.schemas import (
    AlertSeverity,
    SecurityAlert,
    SecurityEvent,
)


def make_event(**overrides):
    event = {
        "event_id": uuid4(),
        "timestamp": "2026-10-28T10:00:00Z",
        "event_type": "login",
        "outcome": "failure",
        "source_ip": "192.0.2.10",
        "user_id": "test-user",
    }
    event.update(overrides)
    return event


def test_valid_event_is_accepted():
    event = SecurityEvent.model_validate(make_event())

    assert event.event_type == "login"
    assert event.source_ip == "192.0.2.10"
    assert event.timestamp.tzinfo is not None


def test_naive_timestamp_is_rejected():
    with pytest.raises(ValidationError):
        SecurityEvent.model_validate(make_event(timestamp="2026-10-28T10:00:00"))


def test_invalid_ip_is_rejected():
    with pytest.raises(ValidationError):
        SecurityEvent.model_validate(make_event(source_ip="not-an-ip"))


def test_unknown_event_field_is_rejected():
    with pytest.raises(ValidationError):
        SecurityEvent.model_validate(make_event(password="secret"))


def test_oversized_metadata_is_rejected():
    with pytest.raises(ValidationError):
        SecurityEvent.model_validate(make_event(metadata={"payload": "x" * 5000}))


def test_alert_score_must_be_between_zero_and_one_hundred():
    with pytest.raises(ValidationError):
        SecurityAlert(
            alert_id=uuid4(),
            rule_id="BRUTE_FORCE_LOGIN",
            severity=AlertSeverity.HIGH,
            risk_score=120,
            source_ip="192.0.2.10",
            event_count=5,
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
        )
