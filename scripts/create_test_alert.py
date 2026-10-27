from datetime import datetime, timedelta, timezone
from uuid import uuid4

from app.common.config import get_settings
from app.common.schemas import SecurityEvent
from app.detection.engine import DetectionEngine
from app.storage.detection_store import DetectionStore


def main():
    settings = get_settings()
    engine = DetectionEngine(
        brute_force_threshold=settings.brute_force_threshold,
        brute_force_window_seconds=settings.brute_force_window_seconds,
    )
    store = DetectionStore(settings.sqlite_path, engine)

    # Use a unique source IP for this test.
    source_ip = "198.51.100.77"
    start = datetime.now(timezone.utc) - timedelta(seconds=60)

    records = []

    for index in range(settings.brute_force_threshold):
        event = SecurityEvent(
            event_id=uuid4(),
            timestamp=start + timedelta(seconds=index * 5),
            event_type="login",
            outcome="failure",
            source_ip=source_ip,
            user_id="synthetic-test-user",
            resource="/login",
        )

        records.append(
            {
                "sequence_number": f"test-{uuid4()}",
                "event": event,
                "error": None,
            }
        )

    # Each test record has a synthetic sequence number.
    # Use a dedicated test shard so the production consumer checkpoint
    # is not modified.
    store.persist_detected_batch(
        shard_id="test-shard-summarization",
        records=records,
    )

    print("Total alerts:", store.count_alerts())
    print("Pending summaries:", len(store.get_pending_alerts()))


if __name__ == "__main__":
    main()
