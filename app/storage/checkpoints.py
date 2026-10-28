import json
import sqlite3
from pathlib import Path
from typing import Any

from app.common.schemas import SecurityEvent


class CheckpointStore:
    """SQLite persistence for consumed events and Kinesis checkpoints."""

    def __init__(self, database_path: str):
        self.database_path = database_path

        if database_path != ":memory:":
            Path(database_path).parent.mkdir(
                parents=True,
                exist_ok=True,
            )

        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self.database_path,
            timeout=10,
        )
        connection.execute("PRAGMA busy_timeout = 10000")
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute("PRAGMA journal_mode = WAL")

            connection.execute("""
                CREATE TABLE IF NOT EXISTS shard_checkpoints (
                    shard_id TEXT PRIMARY KEY,
                    sequence_number TEXT NOT NULL,
                    updated_at TEXT NOT NULL DEFAULT
                        (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
                )
            """)

            connection.execute("""
                CREATE TABLE IF NOT EXISTS consumed_events (
                    event_id TEXT PRIMARY KEY,
                    shard_id TEXT NOT NULL,
                    sequence_number TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    consumed_at TEXT NOT NULL DEFAULT
                        (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                    UNIQUE (shard_id, sequence_number)
                )
            """)

            connection.execute("""
                CREATE TABLE IF NOT EXISTS rejected_records (
                    shard_id TEXT NOT NULL,
                    sequence_number TEXT NOT NULL,
                    error TEXT NOT NULL,
                    rejected_at TEXT NOT NULL DEFAULT
                        (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                    PRIMARY KEY (shard_id, sequence_number)
                )
            """)

    def get_checkpoint(self, shard_id: str) -> str | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT sequence_number
                FROM shard_checkpoints
                WHERE shard_id = ?
                """,
                (shard_id,),
            ).fetchone()

        return row[0] if row else None

    def persist_batch(
        self,
        shard_id: str,
        records: list[dict[str, Any]],
    ) -> None:
        """
        Persist a batch and its checkpoint atomically.

        Each record contains:
          sequence_number: Kinesis sequence number
          event: validated SecurityEvent, or None
          error: rejection reason, or None
        """
        if not records:
            return

        last_sequence_number = records[-1]["sequence_number"]

        with self._connect() as connection:
            # All inserts and the checkpoint update are in one transaction.
            connection.execute("BEGIN IMMEDIATE")

            for record in records:
                sequence_number = record["sequence_number"]
                event = record["event"]
                error = record["error"]

                if event is not None:
                    payload = event.model_dump_json()

                    connection.execute(
                        """
                        INSERT OR IGNORE INTO consumed_events (
                            event_id, shard_id, sequence_number, payload
                        ) VALUES (?, ?, ?, ?)
                        """,
                        (
                            str(event.event_id),
                            shard_id,
                            sequence_number,
                            payload,
                        ),
                    )
                else:
                    connection.execute(
                        """
                        INSERT OR IGNORE INTO rejected_records (
                            shard_id, sequence_number, error
                        ) VALUES (?, ?, ?)
                        """,
                        (
                            shard_id,
                            sequence_number,
                            str(error)[:500],
                        ),
                    )

            connection.execute(
                """
                INSERT INTO shard_checkpoints (
                    shard_id, sequence_number, updated_at
                ) VALUES (
                    ?, ?, strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                )
                ON CONFLICT(shard_id) DO UPDATE SET
                    sequence_number = excluded.sequence_number,
                    updated_at = excluded.updated_at
                """,
                (shard_id, last_sequence_number),
            )

            connection.commit()

    def count_events(self) -> int:
        with self._connect() as connection:
            return connection.execute(
                "SELECT COUNT(*) FROM consumed_events"
            ).fetchone()[0]

    def count_rejected(self) -> int:
        with self._connect() as connection:
            return connection.execute(
                "SELECT COUNT(*) FROM rejected_records"
            ).fetchone()[0]


def reset_stale_checkpoints(database_path: str) -> int:
    """
    Delete saved Kinesis shard checkpoints after a stream is recreated.

    Preserves consumed events, rejected records, alerts, and audit history.

    Returns:
        Number of checkpoint records deleted.
    """
    connection = sqlite3.connect(database_path, timeout=10)

    try:
        connection.execute("PRAGMA busy_timeout = 10000")
        connection.execute("BEGIN IMMEDIATE")

        cursor = connection.execute("DELETE FROM shard_checkpoints")
        deleted_count = cursor.rowcount

        connection.commit()
        return deleted_count

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()


if __name__ == "__main__":
    from app.common.config import Settings

    config = Settings()

    deleted = reset_stale_checkpoints(config.sqlite_path)

    print(f"Reset complete. Deleted {deleted} shard checkpoint(s).")
