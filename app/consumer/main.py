import argparse
import json
import logging
import time
from prometheus_client import start_http_server

from app.observability.metrics import (
    ALERTS_CREATED,
    BATCH_PROCESSING_SECONDS,
    CONSUMER_BATCHES,
    CONSUMER_ERRORS,
    EVENTS_PROCESSED,
    RECORDS_REJECTED,
)

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError
from pydantic import ValidationError

from app.common.config import get_settings
from app.common.schemas import SecurityEvent
from app.detection.engine import DetectionEngine
from app.storage.detection_store import DetectionStore

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


def create_kinesis_client():
    settings = get_settings()
    return boto3.client(
        "kinesis",
        region_name=settings.aws_region,
        config=Config(
            retries={"max_attempts": 5, "mode": "standard"},
            connect_timeout=5,
            read_timeout=30,
        ),
    )


def discover_shards(client, stream_name: str) -> list[str]:
    shard_ids = []
    next_token = None

    while True:
        params = {"StreamName": stream_name}
        if next_token:
            params = {"NextToken": next_token}

        response = client.list_shards(**params)
        shard_ids.extend(shard["ShardId"] for shard in response.get("Shards", []))

        next_token = response.get("NextToken")
        if not next_token:
            return shard_ids


def create_iterator(
    client,
    stream_name: str,
    shard_id: str,
    store: DetectionStore,
) -> str | None:
    checkpoint = store.get_checkpoint(shard_id)

    if checkpoint:
        iterator_type = "AFTER_SEQUENCE_NUMBER"
        params = {"StartingSequenceNumber": checkpoint}
    else:
        iterator_type = "TRIM_HORIZON"
        params = {}

    response = client.get_shard_iterator(
        StreamName=stream_name,
        ShardId=shard_id,
        ShardIteratorType=iterator_type,
        **params,
    )

    return response.get("ShardIterator")


def validate_record(record: dict) -> dict:
    """Convert a Kinesis record into a validated event or rejection."""
    sequence_number = record["SequenceNumber"]

    try:
        payload = json.loads(record["Data"].decode("utf-8"))
        event = SecurityEvent.model_validate(payload)

        return {
            "sequence_number": sequence_number,
            "event": event,
            "error": None,
        }

    except (
        KeyError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        ValidationError,
        TypeError,
    ) as exc:
        return {
            "sequence_number": sequence_number,
            "event": None,
            "error": f"{type(exc).__name__}: {exc}",
        }


def consume_stream(
    client,
    stream_name: str,
    store: DetectionStore,
    poll_interval: float = 1.0,
    max_polls: int | None = None,
    once: bool = False,
) -> None:
    """
    Consume discovered shards round-robin.

    Each batch is committed before its iterator advances locally.
    Set once=True to poll each discovered shard at most once.
    """
    shard_ids = discover_shards(client, stream_name)

    if not shard_ids:
        logger.warning("No shards found for stream %s", stream_name)
        return

    iterators = {
        shard_id: create_iterator(client, stream_name, shard_id, store)
        for shard_id in shard_ids
    }

    polls = 0

    while iterators:
        for shard_id in list(iterators):
            iterator = iterators[shard_id]

            if iterator is None:
                del iterators[shard_id]
                continue

            try:
                response = client.get_records(
                    ShardIterator=iterator,
                    Limit=100,
                )

            except ClientError as exc:
                CONSUMER_ERRORS.inc()

                if exc.response["Error"]["Code"] == "ExpiredIteratorException":
                    logger.info(
                        "Iterator expired; resuming shard %s from checkpoint",
                        shard_id,
                    )
                    iterators[shard_id] = create_iterator(
                        client, stream_name, shard_id, store
                    )
                    continue

                raise

            records = response.get("Records", [])

            if records:
                started = time.perf_counter()

                try:
                    batch = [validate_record(record) for record in records]

                    valid_count = sum(record["event"] is not None for record in batch)
                    rejected_count = len(batch) - valid_count

                    alerts_before = store.count_alerts()

                    # Persist events, detection results, and checkpoint atomically.
                    store.persist_detected_batch(shard_id, batch)

                    alerts_after = store.count_alerts()

                    EVENTS_PROCESSED.inc(valid_count)
                    RECORDS_REJECTED.inc(rejected_count)
                    ALERTS_CREATED.inc(max(0, alerts_after - alerts_before))
                    CONSUMER_BATCHES.inc()

                    logger.info(
                        "Batch committed: shard=%s records=%d valid=%d "
                        "rejected=%d alerts=%d",
                        shard_id,
                        len(batch),
                        valid_count,
                        rejected_count,
                        alerts_after,
                    )

                except Exception:
                    CONSUMER_ERRORS.inc()
                    logger.exception(
                        "Failed processing batch for shard %s",
                        shard_id,
                    )
                    raise

                finally:
                    BATCH_PROCESSING_SECONDS.observe(time.perf_counter() - started)

            # Advance the local iterator only after successful persistence.
            iterators[shard_id] = response.get("NextShardIterator")
            polls += 1

            if max_polls is not None and polls >= max_polls:
                logger.info("Reached poll limit; exiting")
                return

        if once:
            logger.info("Completed one polling round; exiting")
            return

        time.sleep(poll_interval)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Consume Kinesis events with persistent detection."
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Poll each discovered shard once and exit.",
    )
    args = parser.parse_args()

    settings = get_settings()
    client = create_kinesis_client()

    engine = DetectionEngine(
        brute_force_threshold=settings.brute_force_threshold,
        brute_force_window_seconds=settings.brute_force_window_seconds,
    )
    store = DetectionStore(settings.sqlite_path, engine)

    start_http_server(9101)
    logger.info("Consumer metrics available on port 9101")

    try:
        consume_stream(
            client,
            settings.kinesis_stream_name,
            store,
            once=args.once,
        )
    except (BotoCoreError, ClientError):
        logger.exception("Kinesis consumer failed")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
