import json
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from app.common.schemas import (
    AlertStatus,
    SecurityAlert,
    SummaryStatus,
)
from app.detection.engine import DetectionEngine
from app.storage.checkpoints import CheckpointStore


class DetectionStore(CheckpointStore):
    """Persist events, detection state, alerts, and checkpoints atomically."""

    def _connect(self) -> sqlite3.Connection:
        """Return SQLite rows that support both named and positional access."""
        connection = super()._connect()
        connection.row_factory = sqlite3.Row
        return connection

    def __init__(self, database_path: str, engine: DetectionEngine):
        super().__init__(database_path)
        self.engine = engine

        with self._connect() as connection:
            connection.execute("""
                CREATE TABLE IF NOT EXISTS failed_login_attempts (
                    attempt_id TEXT PRIMARY KEY,
                    source_ip TEXT NOT NULL,
                    event_timestamp TEXT NOT NULL
                )
            """)
            connection.execute("""
                CREATE INDEX IF NOT EXISTS idx_failed_login_ip_time
                ON failed_login_attempts(source_ip, event_timestamp)
            """)
            connection.execute("""
                CREATE TABLE IF NOT EXISTS persisted_alerts (
                    dedupe_key TEXT PRIMARY KEY,
                    alert_id TEXT NOT NULL UNIQUE,
                    rule_id TEXT NOT NULL,
                    source_ip TEXT NOT NULL,
                    alert_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
            """)

            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_events (
                    audit_id TEXT PRIMARY KEY,
                    actor_sub TEXT NOT NULL,
                    action TEXT NOT NULL,
                    resource_type TEXT NOT NULL,
                    resource_id TEXT NOT NULL,
                    occurred_at TEXT NOT NULL,
                    outcome TEXT NOT NULL,
                    details TEXT NOT NULL
                )
                """
            )

            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_audit_resource_time
                ON audit_events(resource_type, resource_id, occurred_at)
                """
            )

            existing_columns = {
                row[1]
                for row in connection.execute(
                    "PRAGMA table_info(persisted_alerts)"
                ).fetchall()
            }

            migrations = {
                "summary_claimed_by": "TEXT",
                "summary_lease_until": "TEXT",
                "summary_attempts": "INTEGER NOT NULL DEFAULT 0",
                "summary_next_retry_at": "TEXT",
                "summary_last_error": "TEXT",
            }

            for column, definition in migrations.items():
                if column not in existing_columns:
                    connection.execute(
                        f"ALTER TABLE persisted_alerts ADD COLUMN {column} {definition}"
                    )

    def persist_detected_batch(
        self,
        shard_id: str,
        records: list[dict],
    ) -> None:
        """
        Atomically persist a batch and its detection results.

        Each record contains sequence_number, event, and error.
        """
        if not records:
            return

        connection = self._connect()

        try:
            connection.execute("BEGIN IMMEDIATE")

            for record in records:
                sequence_number = record["sequence_number"]
                event = record["event"]
                error = record["error"]

                if event is None:
                    connection.execute(
                        """
                        INSERT OR IGNORE INTO rejected_records
                            (shard_id, sequence_number, error)
                        VALUES (?, ?, ?)
                        """,
                        (shard_id, sequence_number, str(error)[:500]),
                    )
                    continue

                cursor = connection.execute(
                    """
                    INSERT OR IGNORE INTO consumed_events
                        (event_id, shard_id, sequence_number, payload)
                    VALUES (?, ?, ?, ?)
                    """,
                    (
                        str(event.event_id),
                        shard_id,
                        sequence_number,
                        event.model_dump_json(),
                    ),
                )

                # A replayed event must not generate another detection.
                if cursor.rowcount == 0:
                    continue

                history = self._load_history(
                    connection,
                    event.source_ip,
                )

                findings, risk, updated_history = self.engine.evaluate_with_history(
                    event, history
                )

                self._save_history(
                    connection,
                    event.source_ip,
                    updated_history,
                )

                for finding in findings:
                    if finding.rule_id == "BRUTE_FORCE_LOGIN":
                        dedupe_key = (
                            f"{finding.rule_id}:{finding.source_ip}:"
                            f"{finding.first_seen.isoformat()}"
                        )
                    else:
                        dedupe_key = f"{finding.rule_id}:{event.event_id}"

                    alert = SecurityAlert(
                        alert_id=uuid4(),
                        rule_id=finding.rule_id,
                        severity=risk.severity,
                        risk_score=risk.score,
                        source_ip=finding.source_ip,
                        event_count=finding.event_count,
                        first_seen=finding.first_seen,
                        last_seen=finding.last_seen,
                        status=AlertStatus.OPEN,
                        summary_status=SummaryStatus.PENDING,
                        summary=None,
                        evidence={
                            "description": finding.description,
                            "rule_evidence": finding.evidence,
                            "risk_reasons": list(risk.reasons),
                        },
                    )

                    connection.execute(
                        """
                        INSERT OR IGNORE INTO persisted_alerts (
                            dedupe_key, alert_id, rule_id, source_ip,
                            alert_json, created_at
                        ) VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (
                            dedupe_key,
                            str(alert.alert_id),
                            alert.rule_id,
                            alert.source_ip,
                            alert.model_dump_json(),
                            datetime.now(timezone.utc).isoformat(),
                        ),
                    )

            last_sequence_number = records[-1]["sequence_number"]

            connection.execute(
                """
                INSERT INTO shard_checkpoints
                    (shard_id, sequence_number, updated_at)
                VALUES (?, ?, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
                ON CONFLICT(shard_id) DO UPDATE SET
                    sequence_number = excluded.sequence_number,
                    updated_at = excluded.updated_at
                """,
                (shard_id, last_sequence_number),
            )

            connection.commit()

        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    @staticmethod
    def _load_history(
        connection: sqlite3.Connection,
        source_ip: str,
    ) -> list[datetime]:
        rows = connection.execute(
            """
            SELECT event_timestamp
            FROM failed_login_attempts
            WHERE source_ip = ?
            ORDER BY event_timestamp
            """,
            (source_ip,),
        ).fetchall()

        return [datetime.fromisoformat(timestamp) for (timestamp,) in rows]

    @staticmethod
    def _save_history(
        connection: sqlite3.Connection,
        source_ip: str,
        timestamps: list[datetime],
    ) -> None:
        connection.execute(
            "DELETE FROM failed_login_attempts WHERE source_ip = ?",
            (source_ip,),
        )

        connection.executemany(
            """
            INSERT INTO failed_login_attempts
                (attempt_id, source_ip, event_timestamp)
            VALUES (?, ?, ?)
            """,
            [
                (str(uuid4()), source_ip, timestamp.isoformat())
                for timestamp in timestamps
            ],
        )

    def count_alerts(self) -> int:
        connection = self._connect()
        try:
            return connection.execute(
                "SELECT COUNT(*) FROM persisted_alerts"
            ).fetchone()[0]
        finally:
            connection.close()

    def get_alerts(self) -> list[dict]:
        connection = self._connect()
        try:
            rows = connection.execute(
                """
                SELECT alert_json
                FROM persisted_alerts
                ORDER BY created_at
                """
            ).fetchall()
            return [json.loads(row[0]) for row in rows]
        finally:
            connection.close()

    def get_pending_alerts(
        self,
        limit: int = 10,
        include_failed: bool = False,
    ) -> list[dict]:
        connection = self._connect()
        try:
            rows = connection.execute(
                """
                SELECT alert_json
                FROM persisted_alerts
                ORDER BY created_at
                """
            ).fetchall()

            alerts = [json.loads(row[0]) for row in rows]
            allowed_statuses = {"pending"}
            if include_failed:
                allowed_statuses.add("failed")

            return [
                alert
                for alert in alerts
                if alert.get("summary_status") in allowed_statuses
            ][:limit]
        finally:
            connection.close()

    def update_alert_summary(
        self,
        alert_id: str,
        summary_json: str,
        summary_status: str,
    ) -> bool:
        """Update summary fields without changing risk or alert status."""
        if summary_status not in {"complete", "failed", "pending"}:
            raise ValueError("Invalid summary status")

        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")

            row = connection.execute(
                """
                SELECT alert_json
                FROM persisted_alerts
                WHERE alert_id = ?
                """,
                (alert_id,),
            ).fetchone()

            if row is None:
                connection.rollback()
                return False

            alert = json.loads(row[0])
            alert["summary"] = summary_json if summary_status == "complete" else None
            alert["summary_status"] = summary_status

            connection.execute(
                """
                UPDATE persisted_alerts
                SET alert_json = ?
                WHERE alert_id = ?
                """,
                (json.dumps(alert), alert_id),
            )

            connection.commit()
            return True
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def claim_pending_alerts(
        self,
        worker_id: str,
        limit: int = 10,
        lease_seconds: int = 120,
        max_attempts: int = 3,
        include_failed: bool = False,
    ) -> list[dict]:
        """Atomically claim eligible alerts for one summarization worker."""
        if limit < 1 or lease_seconds < 1 or max_attempts < 1:
            raise ValueError("limit, lease_seconds, and max_attempts must be positive")

        now = datetime.now(timezone.utc)
        now_iso = now.isoformat()
        lease_until = (now + timedelta(seconds=lease_seconds)).isoformat()
        claimed = []

        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")

            rows = connection.execute(
                """
                SELECT alert_id, alert_json, summary_claimed_by,
                       summary_lease_until, summary_attempts,
                       summary_next_retry_at
                FROM persisted_alerts
                ORDER BY created_at
                """
            ).fetchall()

            for (
                alert_id,
                alert_json,
                claimed_by,
                current_lease,
                attempts,
                next_retry,
            ) in rows:
                if len(claimed) >= limit:
                    break

                alert = json.loads(alert_json)
                status = alert.get("summary_status")

                is_failed_retry = include_failed and status == "failed"
                if status != "pending" and not is_failed_retry:
                    continue

                if current_lease and current_lease > now_iso:
                    continue

                if next_retry and next_retry > now_iso and not is_failed_retry:
                    continue

                if attempts >= max_attempts and not is_failed_retry:
                    alert["summary_status"] = "failed"
                    connection.execute(
                        """
                        UPDATE persisted_alerts
                        SET alert_json = ?
                        WHERE alert_id = ?
                        """,
                        (json.dumps(alert), alert_id),
                    )
                    continue

                # Explicit manual retries start a fresh retry cycle.
                if is_failed_retry:
                    attempts = 0

                connection.execute(
                    """
                    UPDATE persisted_alerts
                    SET summary_claimed_by = ?,
                        summary_lease_until = ?,
                        summary_attempts = ?,
                        summary_next_retry_at = NULL,
                        summary_last_error = NULL
                    WHERE alert_id = ?
                    """,
                    (worker_id, lease_until, attempts + 1, alert_id),
                )

                alert["_summary_attempt"] = attempts + 1
                claimed.append(alert)

            connection.commit()
            return claimed
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def complete_claimed_summary(
        self,
        alert_id: str,
        worker_id: str,
        summary_json: str,
    ) -> bool:
        """Complete a summary only if this worker still owns the claim."""
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")

            row = connection.execute(
                """
                SELECT alert_json
                FROM persisted_alerts
                WHERE alert_id = ? AND summary_claimed_by = ?
                """,
                (alert_id, worker_id),
            ).fetchone()

            if row is None:
                connection.rollback()
                return False

            alert = json.loads(row[0])
            alert["summary"] = summary_json
            alert["summary_status"] = "complete"

            connection.execute(
                """
                UPDATE persisted_alerts
                SET alert_json = ?,
                    summary_claimed_by = NULL,
                    summary_lease_until = NULL,
                    summary_next_retry_at = NULL,
                    summary_last_error = NULL
                WHERE alert_id = ?
                """,
                (json.dumps(alert), alert_id),
            )

            connection.commit()
            return True
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def fail_claimed_summary(
        self,
        alert_id: str,
        worker_id: str,
        error: str,
        max_attempts: int = 3,
    ) -> bool:
        """Record a failure and schedule a bounded exponential-backoff retry."""
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")

            row = connection.execute(
                """
                SELECT alert_json, summary_attempts
                FROM persisted_alerts
                WHERE alert_id = ? AND summary_claimed_by = ?
                """,
                (alert_id, worker_id),
            ).fetchone()

            if row is None:
                connection.rollback()
                return False

            alert = json.loads(row[0])
            attempts = row[1]
            exhausted = attempts >= max_attempts

            alert["summary"] = None
            alert["summary_status"] = "failed" if exhausted else "pending"

            retry_seconds = min(2 ** max(attempts - 1, 0), 60)
            next_retry = (
                None
                if exhausted
                else (
                    datetime.now(timezone.utc) + timedelta(seconds=retry_seconds)
                ).isoformat()
            )

            connection.execute(
                """
                UPDATE persisted_alerts
                SET alert_json = ?,
                    summary_claimed_by = NULL,
                    summary_lease_until = NULL,
                    summary_next_retry_at = ?,
                    summary_last_error = ?
                WHERE alert_id = ?
                """,
                (
                    json.dumps(alert),
                    next_retry,
                    error[:1000],
                    alert_id,
                ),
            )

            connection.commit()
            return True
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def list_alerts(
        self,
        limit: int = 50,
        offset: int = 0,
        severity: str | None = None,
        status: str | None = None,
    ) -> list[dict]:
        """List persisted alerts with optional severity/status filters."""
        if not 1 <= limit <= 100:
            raise ValueError("limit must be between 1 and 100")
        if offset < 0:
            raise ValueError("offset must be non-negative")

        connection = self._connect()
        try:
            rows = connection.execute(
                """
                SELECT alert_json
                FROM persisted_alerts
                ORDER BY created_at DESC
                """
            ).fetchall()

            alerts = [json.loads(row[0]) for row in rows]

            if severity is not None:
                alerts = [
                    alert for alert in alerts if alert.get("severity") == severity
                ]

            if status is not None:
                alerts = [alert for alert in alerts if alert.get("status") == status]

            return alerts[offset : offset + limit]
        finally:
            connection.close()

    def get_alert(self, alert_id: str) -> dict | None:
        """Fetch one alert by its ID."""
        connection = self._connect()
        try:
            row = connection.execute(
                """
                SELECT alert_json
                FROM persisted_alerts
                WHERE alert_id = ?
                """,
                (alert_id,),
            ).fetchone()

            return json.loads(row[0]) if row else None
        finally:
            connection.close()

    def transition_alert(
        self,
        *,
        alert_id: str,
        new_status: str,
        actor_sub: str,
        actor_role: str,
    ) -> dict:
        allowed_statuses = {"acknowledged", "resolved"}
        if new_status not in allowed_statuses:
            raise ValueError("Unsupported target status")

        if new_status == "resolved" and actor_role != "admin":
            raise PermissionError("Only admins can resolve alerts")

        connection = self._connect()

        try:
            connection.execute("BEGIN IMMEDIATE")

            row = connection.execute(
                """
                SELECT alert_json
                FROM persisted_alerts
                WHERE alert_id = ?
                """,
                (alert_id,),
            ).fetchone()

            if row is None:
                raise LookupError("Alert not found")

            alert = json.loads(row["alert_json"])
            previous_status = alert["status"]

            allowed_transitions = {
                "open": {"acknowledged", "resolved"},
                "acknowledged": {"resolved"},
                "resolved": set(),
            }

            if new_status not in allowed_transitions.get(previous_status, set()):
                raise ValueError(
                    f"Cannot transition alert from {previous_status} to {new_status}"
                )

            now = datetime.now(timezone.utc).isoformat()
            alert["status"] = new_status

            connection.execute(
                """
                UPDATE persisted_alerts
                SET alert_json = ?
                WHERE alert_id = ?
                """,
                (json.dumps(alert), alert_id),
            )

            connection.execute(
                """
                INSERT INTO audit_events (
                    audit_id,
                    actor_sub,
                    action,
                    resource_type,
                    resource_id,
                    occurred_at,
                    outcome,
                    details
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(uuid.uuid4()),
                    actor_sub,
                    f"alert.{new_status}",
                    "alert",
                    alert_id,
                    now,
                    "success",
                    json.dumps(
                        {
                            "previous_status": previous_status,
                            "new_status": new_status,
                            "actor_role": actor_role,
                        }
                    ),
                ),
            )

            connection.commit()
            return alert

        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def list_audit_events(
        self,
        limit: int = 50,
        offset: int = 0,
        resource_id: str | None = None,
    ) -> list[dict]:
        """List audit events, newest first."""
        if not 1 <= limit <= 100:
            raise ValueError("limit must be between 1 and 100")
        if offset < 0:
            raise ValueError("offset must be non-negative")

        connection = self._connect()
        try:
            if resource_id is None:
                rows = connection.execute(
                    """
                    SELECT audit_id, actor_sub, action, resource_type,
                        resource_id, occurred_at, outcome, details
                    FROM audit_events
                    ORDER BY occurred_at DESC, audit_id DESC
                    LIMIT ? OFFSET ?
                    """,
                    (limit, offset),
                ).fetchall()
            else:
                rows = connection.execute(
                    """
                    SELECT audit_id, actor_sub, action, resource_type,
                        resource_id, occurred_at, outcome, details
                    FROM audit_events
                    WHERE resource_id = ?
                    ORDER BY occurred_at DESC, audit_id DESC
                    LIMIT ? OFFSET ?
                    """,
                    (resource_id, limit, offset),
                ).fetchall()

            events = []
            for row in rows:
                event = dict(row)
                event["details"] = json.loads(event["details"])
                events.append(event)

            return events
        finally:
            connection.close()
