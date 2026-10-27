import argparse
import json
import logging
import random
import time
from uuid import uuid4
from datetime import datetime, timezone

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

from app.common.config import get_settings
from app.common.schemas import SecurityEvent

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


def generate_event() -> SecurityEvent:
    """Generate one validated synthetic security event."""

    event_type = random.choice(["login", "resource_access"])

    if event_type == "login":
        outcome = random.choices(
            ["success", "failure"],
            weights=[0.7, 0.3],
            k=1,
        )[0]
        resource = "/login"
    else:
        outcome = random.choices(
            ["success", "denied"],
            weights=[0.8, 0.2],
            k=1,
        )[0]
        resource = "/admin/reports"

    # TEST-NET addresses are reserved for documentation and examples.
    source_ip = random.choice(
        [
            "192.0.2.10",
            "192.0.2.20",
            "198.51.100.15",
            "203.0.113.7",
        ]
    )

    return SecurityEvent(
        event_id=uuid4(),
        timestamp=datetime.now(timezone.utc),
        event_type=event_type,
        outcome=outcome,
        source_ip=source_ip,
        user_id=f"test-user-{random.randint(1, 10)}",
        resource=resource,
        metadata={"generator": "synthetic-v1"},
    )


def publish_events(count: int, batch_size: int = 100) -> int:
    """Publish validated events to Kinesis and return the count sent."""

    if count < 1:
        raise ValueError("count must be at least 1")

    settings = get_settings()

    client = boto3.client(
        "kinesis",
        region_name=settings.aws_region,
        config=Config(
            retries={"max_attempts": 5, "mode": "standard"},
            connect_timeout=5,
            read_timeout=30,
        ),
    )

    published = 0

    while published < count:
        remaining = count - published
        size = min(batch_size, remaining)

        events = [generate_event() for _ in range(size)]

        records = [
            {
                "Data": event.model_dump_json().encode("utf-8"),
                "PartitionKey": event.source_ip,
            }
            for event in events
        ]

        try:
            response = client.put_records(
                StreamName=settings.kinesis_stream_name,
                Records=records,
            )
        except BotoCoreError, ClientError:
            logger.exception("Kinesis request failed")
            raise

        failed_count = response["FailedRecordCount"]

        for event, result in zip(events, response["Records"]):
            if "ErrorCode" in result:
                logger.error(
                    "Event publish failed: event_id=%s error=%s",
                    event.event_id,
                    result.get("ErrorCode"),
                )
            else:
                published += 1
                logger.info(
                    "Event published: event_id=%s type=%s outcome=%s",
                    event.event_id,
                    event.event_type.value,
                    event.outcome.value,
                )

        if failed_count:
            logger.warning(
                "%s records failed; retrying failed records",
                failed_count,
            )

            # Retry only failed records. Keep the original event IDs.
            failed_records = [
                record
                for record, result in zip(records, response["Records"])
                if "ErrorCode" in result
            ]

            for attempt in range(5):
                if not failed_records:
                    break

                time.sleep(min(2**attempt, 10))

                retry_response = client.put_records(
                    StreamName=settings.kinesis_stream_name,
                    Records=failed_records,
                )

                retry_results = retry_response["Records"]
                failed_records = [
                    record
                    for record, result in zip(failed_records, retry_results)
                    if "ErrorCode" in result
                ]

                published += len(retry_results) - len(failed_records)

            if failed_records:
                raise RuntimeError(
                    f"{len(failed_records)} records remain unpublished after retries"
                )

    return published


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Publish synthetic security events to AWS Kinesis."
    )
    parser.add_argument("--count", type=int, default=20)
    args = parser.parse_args()

    try:
        count = publish_events(args.count)
    except BotoCoreError, ClientError, RuntimeError, ValueError:
        logger.exception("Producer failed")
        raise SystemExit(1)

    logger.info("Successfully published %s events", count)


if __name__ == "__main__":
    main()
