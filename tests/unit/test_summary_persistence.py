from datetime import datetime, timezone
from uuid import uuid4

from app.common.schemas import SecurityEvent
from app.detection.engine import DetectionEngine
from app.storage.detection_store import DetectionStore


def test_summary_update_preserves_security_decision(tmp_path):
    store = DetectionStore(
        str(tmp_path / "summary.db"),
        DetectionEngine(brute_force_threshold=1),
    )

    event = SecurityEvent(
        event_id=uuid4(),
        timestamp=datetime(2026, 10, 28, 10, 0, tzinfo=timezone.utc),
        event_type="login",
        outcome="failure",
        source_ip="192.0.2.10",
        user_id="synthetic-user",
        resource="/login",
    )

    store.persist_detected_batch(
        "shard-1",
        [{"sequence_number": "1", "event": event, "error": None}],
    )

    alert = store.get_alerts()[0]
    original_score = alert["risk_score"]
    original_severity = alert["severity"]
    original_status = alert["status"]

    saved = store.update_alert_summary(
        alert_id=alert["alert_id"],
        summary_json=(
            '{"explanation":"Repeated failed login attempt.",'
            '"evidence":["One failed login was observed."],'
            '"recommended_actions":["Review authentication logs."]}'
        ),
        summary_status="complete",
    )

    assert saved is True

    updated = store.get_alerts()[0]
    assert updated["summary_status"] == "complete"
    assert updated["summary"] is not None
    assert updated["risk_score"] == original_score
    assert updated["severity"] == original_severity
    assert updated["status"] == original_status


def test_summary_update_returns_false_for_missing_alert(tmp_path):
    store = DetectionStore(
        str(tmp_path / "summary.db"),
        DetectionEngine(),
    )

    assert (
        store.update_alert_summary(
            alert_id=str(uuid4()),
            summary_json="{}",
            summary_status="complete",
        )
        is False
    )


def test_failed_summaries_can_be_retried(tmp_path):
    store = DetectionStore(
        str(tmp_path / "summary.db"),
        DetectionEngine(brute_force_threshold=1),
    )

    event = SecurityEvent(
        event_id=uuid4(),
        timestamp=datetime(2026, 10, 28, 10, 0, tzinfo=timezone.utc),
        event_type="login",
        outcome="failure",
        source_ip="192.0.2.10",
        user_id="synthetic-user",
        resource="/login",
    )

    store.persist_detected_batch(
        "shard-1",
        [{"sequence_number": "1", "event": event, "error": None}],
    )

    alert = store.get_alerts()[0]
    store.update_alert_summary(
        alert_id=alert["alert_id"],
        summary_json="",
        summary_status="failed",
    )

    assert store.get_pending_alerts() == []
    assert len(store.get_pending_alerts(include_failed=True)) == 1
