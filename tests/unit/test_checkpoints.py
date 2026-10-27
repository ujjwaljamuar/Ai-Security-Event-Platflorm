from datetime import datetime, timezone
from uuid import uuid4

from app.common.schemas import SecurityEvent
from app.storage.checkpoints import CheckpointStore


def make_event(event_id=None):
    return SecurityEvent(
        event_id=event_id or uuid4(),
        timestamp=datetime.now(timezone.utc),
        event_type="login",
        outcome="failure",
        source_ip="192.0.2.10",
        user_id="test-user",
    )


def test_checkpoint_survives_store_restart(tmp_path):
    db_path = str(tmp_path / "events.db")

    store = CheckpointStore(db_path)
    store.persist_batch(
        "shard-001",
        [
            {
                "sequence_number": "100",
                "event": make_event(),
                "error": None,
            }
        ],
    )

    reopened = CheckpointStore(db_path)

    assert reopened.get_checkpoint("shard-001") == "100"
    assert reopened.count_events() == 1


def test_duplicate_event_is_not_inserted_twice(tmp_path):
    store = CheckpointStore(str(tmp_path / "events.db"))
    event = make_event()

    store.persist_batch(
        "shard-001",
        [{"sequence_number": "100", "event": event, "error": None}],
    )
    store.persist_batch(
        "shard-001",
        [{"sequence_number": "101", "event": event, "error": None}],
    )

    assert store.count_events() == 1
    assert store.get_checkpoint("shard-001") == "101"


def test_rejected_record_is_persisted_and_checkpointed(tmp_path):
    store = CheckpointStore(str(tmp_path / "events.db"))

    store.persist_batch(
        "shard-001",
        [
            {
                "sequence_number": "200",
                "event": None,
                "error": "invalid JSON",
            }
        ],
    )

    assert store.count_rejected() == 1
    assert store.get_checkpoint("shard-001") == "200"


def test_empty_batch_does_not_advance_checkpoint(tmp_path):
    store = CheckpointStore(str(tmp_path / "events.db"))

    store.persist_batch("shard-001", [])

    assert store.get_checkpoint("shard-001") is None
