from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from app.common.schemas import SecurityEvent
from app.detection.engine import DetectionEngine
from app.storage.detection_store import DetectionStore


def make_record(sequence, second, outcome="failure"):
    event = SecurityEvent(
        event_id=uuid4(),
        timestamp=datetime(2026, 10, 28, 10, 0, tzinfo=timezone.utc)
        + timedelta(seconds=second),
        event_type="login",
        outcome=outcome,
        source_ip="192.0.2.10",
        user_id="synthetic-user",
        resource="/login",
    )
    return {
        "sequence_number": str(sequence),
        "event": event,
        "error": None,
    }


def make_store(path):
    return DetectionStore(
        str(path),
        DetectionEngine(
            brute_force_threshold=5,
            brute_force_window_seconds=300,
        ),
    )


def test_detection_state_survives_store_restart(tmp_path):
    db = tmp_path / "events.db"
    store = make_store(db)

    for sequence, second in enumerate((0, 30, 60, 90), start=1):
        store.persist_detected_batch(
            "shard-1",
            [make_record(sequence, second)],
        )

    assert store.count_alerts() == 0

    # New store and engine simulate a process restart.
    restarted_store = make_store(db)
    restarted_store.persist_detected_batch(
        "shard-1",
        [make_record(5, 120)],
    )

    assert restarted_store.count_alerts() == 1
    assert restarted_store.get_checkpoint("shard-1") == "5"


def test_replayed_record_does_not_create_duplicate_alert(tmp_path):
    store = make_store(tmp_path / "events.db")

    records = [
        make_record(sequence, second)
        for sequence, second in enumerate((0, 30, 60, 90, 120), start=1)
    ]

    for record in records:
        store.persist_detected_batch("shard-1", [record])

    assert store.count_alerts() == 1

    # Replay the fifth record.
    store.persist_detected_batch("shard-1", [records[-1]])

    assert store.count_events() == 5
    assert store.count_alerts() == 1


def test_failed_transaction_rolls_back_event_and_checkpoint(
    tmp_path,
    monkeypatch,
):
    store = make_store(tmp_path / "events.db")

    def fail_save_history(*args, **kwargs):
        raise RuntimeError("simulated database-processing failure")

    monkeypatch.setattr(store, "_save_history", fail_save_history)

    with pytest.raises(RuntimeError, match="simulated database-processing failure"):
        store.persist_detected_batch(
            "shard-1",
            [make_record(1, 0)],
        )

    assert store.count_events() == 0
    assert store.get_checkpoint("shard-1") is None


def test_non_login_event_does_not_add_brute_force_attempts(tmp_path):
    store = make_store(tmp_path / "events.db")

    event = make_record(1, 0, outcome="success")
    store.persist_detected_batch("shard-1", [event])

    connection = store._connect()
    try:
        count = connection.execute(
            "SELECT COUNT(*) FROM failed_login_attempts"
        ).fetchone()[0]
    finally:
        connection.close()

    assert count == 0
