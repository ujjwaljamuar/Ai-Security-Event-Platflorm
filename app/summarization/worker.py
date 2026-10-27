import argparse
import json
import logging

from app.observability.metrics import (
    SUMMARY_ATTEMPTS,
    SUMMARY_FAILURES,
    SUMMARY_SUCCESSES,
)

from app.common.config import get_settings
from app.detection.engine import DetectionEngine
from app.storage.detection_store import DetectionStore
from app.summarization.openai_provider import generate_alert_summary

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


def run_worker(limit: int = 10, retry_failed: bool = False) -> int:
    settings = get_settings()
    store = DetectionStore(
        settings.sqlite_path,
        DetectionEngine(
            brute_force_threshold=settings.brute_force_threshold,
            brute_force_window_seconds=settings.brute_force_window_seconds,
        ),
    )

    alerts = store.get_pending_alerts(
        limit=limit,
        include_failed=retry_failed,
    )

    if not alerts:
        logger.info("No alerts need summarization.")
        return 0

    failures = 0

    for alert in alerts:
        alert_id = str(alert["alert_id"])
        SUMMARY_ATTEMPTS.inc()

        try:
            summary = generate_alert_summary(alert)

            saved = store.update_alert_summary(
                alert_id=alert_id,
                summary_json=summary.model_dump_json(),
                summary_status="complete",
            )

            if not saved:
                raise RuntimeError("Alert disappeared before summary was saved")

            SUMMARY_SUCCESSES.inc()
            logger.info("Summary saved for alert_id=%s", alert_id)

        except Exception:
            failures += 1
            SUMMARY_FAILURES.inc()

            logger.exception(
                "Summary generation failed for alert_id=%s",
                alert_id,
            )

            store.update_alert_summary(
                alert_id=alert_id,
                summary_json="",
                summary_status="failed",
            )

    return 1 if failures else 0


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate summaries for persisted security alerts."
    )
    parser.add_argument("--limit", type=int, default=10)
    parser.add_argument(
        "--retry-failed",
        action="store_true",
        help="Retry alerts whose previous summary generation failed.",
    )
    args = parser.parse_args()

    if args.limit < 1:
        parser.error("--limit must be at least 1")

    raise SystemExit(run_worker(args.limit, args.retry_failed))


if __name__ == "__main__":
    main()
