from datetime import datetime, timezone
from uuid import uuid4

from app.common.schemas import SecurityEvent
from app.detection.engine import DetectionEngine
from app.storage.detection_store import DetectionStore


def create_alert_store(path):
    store = DetectionStore(
        str(path),
        DetectionEngine(brute_force_threshold=1),
    )

    event = SecurityEvent(
        event_id=uuid4(),
        timestamp=datetime(2026, 10, 28, 10, 0, tzinfo=timezone.utc),
        event_type="login",
        outcome="failure",
        source_ip="198.51.100.25",
        user_id="synthetic-user",
        resource="/login",
    )

    store.persist_detected_batch(
        "test-shard",
        [{"sequence_number": "test-1", "event": event, "error": None}],
    )
    return store


def test_only_one_worker_claims_pending_alert(tmp_path):
    store = create_alert_store(tmp_path / "claims.db")

    first = store.claim_pending_alerts("worker-a", limit=10)
    second = store.claim_pending_alerts("worker-b", limit=10)

    assert len(first) == 1
    assert second == []


def test_only_claim_owner_can_complete_summary(tmp_path):
    store = create_alert_store(tmp_path / "ownership.db")
    alert = store.claim_pending_alerts("worker-a")[0]

    summary_json = (
        '{"explanation":"One failed login was observed.",'
        '"evidence":["A failed login event was recorded."],'
        '"recommended_actions":["Review authentication logs."]}'
    )

    assert (
        store.complete_claimed_summary(
            alert["alert_id"],
            "worker-b",
            summary_json,
        )
        is False
    )

    assert (
        store.complete_claimed_summary(
            alert["alert_id"],
            "worker-a",
            summary_json,
        )
        is True
    )


def test_failure_preserves_risk_decision(tmp_path):
    store = create_alert_store(tmp_path / "failure.db")
    alert = store.claim_pending_alerts("worker-a")[0]

    assert store.fail_claimed_summary(
        alert["alert_id"],
        "worker-a",
        "simulated provider failure",
    )

    updated = store.get_alerts()[0]

    assert updated["summary_status"] == "pending"
    assert updated["risk_score"] == alert["risk_score"]
    assert updated["severity"] == alert["severity"]
    assert updated["status"] == alert["status"]
