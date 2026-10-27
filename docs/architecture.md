
# Architecture and Processing Contracts

## Event flow

Synthetic producer -> Kinesis -> Python consumer ->
detection engine -> SQLite alert store -> FastAPI.

Prometheus metrics and structured logs provide observability.

## Event contract

- event_id: unique UUID
- timestamp: timezone-aware UTC datetime
- event_type: login or resource_access
- outcome: success, failure, or denied
- source_ip: valid IPv4 or IPv6 address
- user_id: synthetic identifier
- resource: optional resource path
- metadata: bounded contextual data

## Alert contract

- alert_id: unique UUID
- rule_id: stable detection rule identifier
- severity: low, medium, high, or critical
- risk_score: integer from 0 through 100
- source_ip: validated IP address
- event_count: positive integer
- first_seen and last_seen: timezone-aware timestamps
- status: open, acknowledged, or resolved
- summary_status: pending, complete, failed, or not_required

## Delivery and recovery

The consumer uses at-least-once delivery semantics.

SQLite transactions will atomically persist:
- deduplication records
- alert changes
- detection state
- the last processed Kinesis sequence number

A checkpoint must never advance ahead of the committed processing results.

LLM calls occur outside the checkpoint transaction.
Summary generation is retriable and must not block core detection.

## Initial deployment limitations

- Single consumer process
- Single SQLite database
- No distributed shard ownership
- Synthetic events only
- No automated response actions
