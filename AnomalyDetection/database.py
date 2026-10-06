from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Iterable

REQUIRED_EVENT_COLUMNS = {
    "id",
    "ts",
    "event_type",
    "flow_id",
    "src_ip",
    "dest_ip",
    "dest_port",
}

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS anomaly_windows (
    src_ip                    TEXT    NOT NULL,
    window_start              TEXT    NOT NULL,
    window_end                TEXT    NOT NULL,
    window_seconds            INTEGER NOT NULL,
    event_count               INTEGER NOT NULL,
    unique_destinations       INTEGER NOT NULL,
    unique_destination_ports  INTEGER NOT NULL,
    unique_flows              INTEGER NOT NULL,
    alert_count               INTEGER NOT NULL,
    PRIMARY KEY (src_ip, window_start, window_seconds)
);

CREATE INDEX IF NOT EXISTS idx_anomaly_windows_time
ON anomaly_windows(window_seconds, window_start);

CREATE INDEX IF NOT EXISTS idx_anomaly_windows_source
ON anomaly_windows(window_seconds, src_ip);

CREATE TABLE IF NOT EXISTS anomaly_baselines (
    scope_type       TEXT    NOT NULL,
    scope_key        TEXT    NOT NULL,
    metric           TEXT    NOT NULL,
    window_seconds   INTEGER NOT NULL,
    median_value     REAL    NOT NULL,
    mad_value        REAL    NOT NULL,
    sample_count     INTEGER NOT NULL,
    PRIMARY KEY (scope_type, scope_key, metric, window_seconds)
);

CREATE TABLE IF NOT EXISTS anomaly_findings (
    finding_id          TEXT PRIMARY KEY,
    detector_name       TEXT    NOT NULL,
    method              TEXT    NOT NULL,
    window_seconds      INTEGER NOT NULL,
    window_start        TEXT    NOT NULL,
    window_end          TEXT    NOT NULL,
    src_ip              TEXT    NOT NULL,
    metric              TEXT    NOT NULL,
    observed_value      REAL    NOT NULL,
    baseline_median     REAL    NOT NULL,
    baseline_mad        REAL    NOT NULL,
    scale_used          REAL    NOT NULL,
    anomaly_score       REAL    NOT NULL,
    threshold           REAL    NOT NULL,
    baseline_scope      TEXT    NOT NULL,
    reason              TEXT    NOT NULL,
    status              TEXT    NOT NULL DEFAULT 'candidate_for_investigation',
    created_at          TEXT    NOT NULL,
    UNIQUE (detector_name, window_seconds, window_start, src_ip, metric)
);

CREATE INDEX IF NOT EXISTS idx_anomaly_findings_source
ON anomaly_findings(src_ip, window_start);

CREATE INDEX IF NOT EXISTS idx_anomaly_findings_score
ON anomaly_findings(anomaly_score DESC);

CREATE TABLE IF NOT EXISTS anomaly_events (
    finding_id  TEXT    NOT NULL,
    event_id    INTEGER NOT NULL,
    flow_id     INTEGER,
    PRIMARY KEY (finding_id, event_id),
    FOREIGN KEY (finding_id)
        REFERENCES anomaly_findings(finding_id)
        ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_anomaly_events_event
ON anomaly_events(event_id);

CREATE INDEX IF NOT EXISTS idx_anomaly_events_flow
ON anomaly_events(flow_id);

CREATE TABLE IF NOT EXISTS anomaly_runs (
    run_id                 TEXT PRIMARY KEY,
    detector_name          TEXT    NOT NULL,
    method                 TEXT    NOT NULL,
    started_at             TEXT    NOT NULL,
    completed_at           TEXT,
    window_seconds         INTEGER NOT NULL,
    threshold              REAL    NOT NULL,
    min_source_windows     INTEGER NOT NULL,
    windows_created        INTEGER NOT NULL DEFAULT 0,
    baselines_created      INTEGER NOT NULL DEFAULT 0,
    findings_created       INTEGER NOT NULL DEFAULT 0,
    event_links_created    INTEGER NOT NULL DEFAULT 0
);
"""


def connect(db_path: str | Path) -> sqlite3.Connection:
    connection = sqlite3.connect(str(db_path))
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA journal_mode = WAL")
    connection.execute("PRAGMA synchronous = NORMAL")
    return connection


def table_exists(connection: sqlite3.Connection, table_name: str) -> bool:
    row = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
        (table_name,),
    ).fetchone()
    return row is not None


def table_columns(connection: sqlite3.Connection, table_name: str) -> set[str]:
    return {
        row["name"]
        for row in connection.execute(f"PRAGMA table_info({table_name})")
    }


def validate_events_table(connection: sqlite3.Connection) -> None:
    if not table_exists(connection, "events"):
        raise RuntimeError(
            "SQLite table 'events' was not found. Run DataInitialFiltering/ingest.py "
            "before anomaly detection."
        )

    columns = table_columns(connection, "events")
    missing = sorted(REQUIRED_EVENT_COLUMNS - columns)
    if missing:
        raise RuntimeError(
            "The events table is missing required columns: " + ", ".join(missing)
        )


def create_anomaly_tables(connection: sqlite3.Connection) -> None:
    connection.executescript(SCHEMA_SQL)
    connection.commit()


def insert_many(
    connection: sqlite3.Connection,
    sql: str,
    rows: Iterable[tuple],
) -> int:
    before = connection.total_changes
    connection.executemany(sql, rows)
    return connection.total_changes - before
