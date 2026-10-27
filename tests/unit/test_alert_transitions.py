import json

import pytest

from app.detection.engine import DetectionEngine
from app.storage.detection_store import DetectionStore


@pytest.fixture
def store(tmp_path):
    database = tmp_path / "test.db"
    instance = DetectionStore(
        str(database),
        DetectionEngine(),
    )

    alert = {
        "alert_id": "alert-test-001",
        "rule_id": "BRUTE_FORCE_LOGIN",
        "severity": "high",
        "risk_score": 70,
        "source_ip": "192.0.2.10",
        "event_count": 5,
        "first_seen": "2026-10-28T10:00:00+00:00",
        "last_seen": "2026-10-28T10:01:00+00:00",
        "status": "open",
        "summary_status": "pending",
        "summary": None,
        "evidence": {},
    }

    connection = instance._connect()
    try:
        connection.execute(
            """
            INSERT INTO persisted_alerts (
                dedupe_key, alert_id, rule_id, source_ip,
                alert_json, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                "test-dedupe-key",
                alert["alert_id"],
                alert["rule_id"],
                alert["source_ip"],
                json.dumps(alert),
                "2026-10-28T10:01:00+00:00",
            ),
        )
        connection.commit()
    finally:
        connection.close()

    return instance


def test_analyst_can_acknowledge_alert(store):
    alert = store.transition_alert(
        alert_id="alert-test-001",
        new_status="acknowledged",
        actor_sub="analyst-001",
        actor_role="analyst",
    )

    assert alert["status"] == "acknowledged"

    connection = store._connect()
    try:
        row = connection.execute(
            """
            SELECT actor_sub, action, outcome, details
            FROM audit_events
            WHERE resource_id = ?
            """,
            ("alert-test-001",),
        ).fetchone()
    finally:
        connection.close()

    assert row[0] == "analyst-001"
    assert row[1] == "alert.acknowledged"
    assert row[2] == "success"

    details = json.loads(row[3])

    # details = json.loads(row["details"])
    assert details["previous_status"] == "open"
    assert details["new_status"] == "acknowledged"


def test_analyst_cannot_resolve_alert(store):
    with pytest.raises(PermissionError):
        store.transition_alert(
            alert_id="alert-test-001",
            new_status="resolved",
            actor_sub="analyst-001",
            actor_role="analyst",
        )


def test_admin_can_resolve_alert(store):
    alert = store.transition_alert(
        alert_id="alert-test-001",
        new_status="resolved",
        actor_sub="admin-001",
        actor_role="admin",
    )

    assert alert["status"] == "resolved"


def test_resolved_alert_cannot_be_reopened(store):
    store.transition_alert(
        alert_id="alert-test-001",
        new_status="resolved",
        actor_sub="admin-001",
        actor_role="admin",
    )

    with pytest.raises(ValueError):
        store.transition_alert(
            alert_id="alert-test-001",
            new_status="acknowledged",
            actor_sub="analyst-001",
            actor_role="analyst",
        )


def test_missing_alert_raises_lookup_error(store):
    with pytest.raises(LookupError):
        store.transition_alert(
            alert_id="missing-alert",
            new_status="acknowledged",
            actor_sub="analyst-001",
            actor_role="analyst",
        )
