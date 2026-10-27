from prometheus_client import Counter, Histogram

# Consumer metrics
EVENTS_PROCESSED = Counter(
    "security_events_processed_total",
    "Number of valid security events successfully persisted.",
)

RECORDS_REJECTED = Counter(
    "security_records_rejected_total",
    "Number of invalid security records persisted as rejected.",
)

ALERTS_CREATED = Counter(
    "security_alerts_created_total",
    "Number of new security alerts persisted.",
)

CONSUMER_BATCHES = Counter(
    "security_consumer_batches_total",
    "Number of Kinesis batches successfully processed.",
)

CONSUMER_ERRORS = Counter(
    "security_consumer_errors_total",
    "Number of errors encountered by the Kinesis consumer.",
)

BATCH_PROCESSING_SECONDS = Histogram(
    "security_consumer_batch_processing_seconds",
    "Time spent validating and persisting each non-empty batch.",
)

# API metrics
API_REQUESTS = Counter(
    "security_api_requests_total",
    "Number of completed API requests.",
    ["method", "status"],
)

API_REQUEST_DURATION = Histogram(
    "security_api_request_duration_seconds",
    "API request processing duration in seconds.",
    ["method"],
)

SUMMARY_ATTEMPTS = Counter(
    "security_summary_attempts_total",
    "Number of AI alert-summary generation attempts.",
)

SUMMARY_SUCCESSES = Counter(
    "security_summary_successes_total",
    "Number of successfully generated and saved alert summaries.",
)

SUMMARY_FAILURES = Counter(
    "security_summary_failures_total",
    "Number of failed alert-summary attempts.",
)
