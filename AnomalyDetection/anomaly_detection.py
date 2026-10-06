from __future__ import annotations

import argparse
import hashlib
import sqlite3
import sys
import uuid
from contextlib import closing
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable

try:
    from .database import (
        connect,
        create_anomaly_tables,
        insert_many,
        validate_events_table,
    )
    from .robust_stats import RobustBaseline, median_absolute_deviation, modified_z_score
except ImportError:  # Allows: python AnomalyDetection/anomaly_detection.py
    from database import (  # type: ignore
        connect,
        create_anomaly_tables,
        insert_many,
        validate_events_table,
    )
    from robust_stats import RobustBaseline, median_absolute_deviation, modified_z_score  # type: ignore

DETECTOR_NAME = "statistical_network_behaviour"
METHOD_NAME = "median_mad_modified_z"
DEFAULT_WINDOW_SECONDS = 60
DEFAULT_THRESHOLD = 3.5
DEFAULT_MIN_SOURCE_WINDOWS = 5
BATCH_SIZE = 5000

METRICS = (
    "event_count",
    "unique_destinations",
    "unique_destination_ports",
    "unique_flows",
    "alert_count",
)

REASONS = {
    "event_count": "Event volume is significantly above the statistical baseline.",
    "unique_destinations": "Source contacted an unusually high number of unique destinations.",
    "unique_destination_ports": "Source contacted an unusually high number of destination ports.",
    "unique_flows": "Source created an unusually high number of network flows.",
    "alert_count": "Source produced an unusually high number of Suricata alert events.",
}


@dataclass
class WindowAccumulator:
    event_count: int = 0
    destinations: set[str] = field(default_factory=set)
    destination_ports: set[int] = field(default_factory=set)
    flows: set[int] = field(default_factory=set)
    alert_count: int = 0

    def add(self, row: sqlite3.Row) -> None:
        self.event_count += 1
        if row["dest_ip"]:
            self.destinations.add(str(row["dest_ip"]))
        if row["dest_port"] is not None:
            self.destination_ports.add(int(row["dest_port"]))
        if row["flow_id"] is not None:
            self.flows.add(int(row["flow_id"]))
        if row["event_type"] == "alert":
            self.alert_count += 1

    def as_values(self) -> tuple[int, int, int, int, int]:
        return (
            self.event_count,
            len(self.destinations),
            len(self.destination_ports),
            len(self.flows),
            self.alert_count,
        )


@dataclass(frozen=True)
class AnalysisResult:
    run_id: str
    windows_created: int
    baselines_created: int
    findings_created: int
    event_links_created: int


def parse_timestamp(value: str) -> datetime:
    timestamp = value.strip()
    if timestamp.endswith("Z"):
        timestamp = timestamp[:-1] + "+00:00"

    # Suricata commonly uses +0000 instead of +00:00.
    if (
        len(timestamp) >= 5
        and timestamp[-5] in ("+", "-")
        and timestamp[-3] != ":"
        and timestamp[-4:].isdigit()
    ):
        timestamp = timestamp[:-2] + ":" + timestamp[-2:]

    parsed = datetime.fromisoformat(timestamp)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def bucket_epoch(timestamp: datetime, window_seconds: int) -> int:
    epoch = int(timestamp.timestamp())
    return (epoch // window_seconds) * window_seconds


def epoch_to_iso(epoch: int) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat(timespec="seconds")


def _flush_window(
    connection: sqlite3.Connection,
    epoch: int,
    window_seconds: int,
    source_windows: dict[str, WindowAccumulator],
) -> int:
    if not source_windows:
        return 0

    start = epoch_to_iso(epoch)
    end = epoch_to_iso(epoch + window_seconds)
    rows = []

    for src_ip, accumulator in source_windows.items():
        event_count, destinations, ports, flows, alerts = accumulator.as_values()
        rows.append(
            (
                src_ip,
                start,
                end,
                window_seconds,
                event_count,
                destinations,
                ports,
                flows,
                alerts,
            )
        )

    sql = """
    INSERT INTO anomaly_windows (
        src_ip, window_start, window_end, window_seconds,
        event_count, unique_destinations, unique_destination_ports,
        unique_flows, alert_count
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(src_ip, window_start, window_seconds) DO UPDATE SET
        window_end = excluded.window_end,
        event_count = excluded.event_count,
        unique_destinations = excluded.unique_destinations,
        unique_destination_ports = excluded.unique_destination_ports,
        unique_flows = excluded.unique_flows,
        alert_count = excluded.alert_count
    """
    insert_many(connection, sql, rows)
    return len(rows)


def build_windows(
    connection: sqlite3.Connection,
    window_seconds: int,
) -> int:
    """Aggregate events into per-source fixed time windows.

    Events are streamed in timestamp order, so raw EVE data is not loaded into
    memory. Only the sources active in the current time window are held in RAM.
    """
    if window_seconds <= 0:
        raise ValueError("window_seconds must be greater than zero")

    connection.execute(
        "DELETE FROM anomaly_windows WHERE window_seconds = ?",
        (window_seconds,),
    )
    connection.execute(
        "DELETE FROM anomaly_baselines WHERE window_seconds = ?",
        (window_seconds,),
    )
    connection.commit()

    cursor = connection.execute(
        """
        SELECT id, ts, event_type, flow_id, src_ip, dest_ip, dest_port
        FROM events
        WHERE ts IS NOT NULL AND src_ip IS NOT NULL
        ORDER BY ts, id
        """
    )

    current_epoch: int | None = None
    source_windows: dict[str, WindowAccumulator] = {}
    windows_created = 0

    for row in cursor:
        try:
            timestamp = parse_timestamp(row["ts"])
        except (TypeError, ValueError):
            # Ingestion should already reject missing timestamps. A malformed
            # timestamp is skipped here instead of breaking the entire run.
            continue

        epoch = bucket_epoch(timestamp, window_seconds)
        if current_epoch is None:
            current_epoch = epoch

        # This prototype expects the Suricata timestamps in the database to be chronologically sortable (the provided data uses UTC +0000). If a later imported file produces an earlier bucket, fail clearly rather than silently building incorrect windows.

        if epoch < current_epoch:
            raise RuntimeError(
                "events.ts is not chronologically sortable across the current dataset. "
                "Normalize timestamps during ingestion before running anomaly detection."
            )

        if epoch != current_epoch:
            windows_created += _flush_window(
                connection,
                current_epoch,
                window_seconds,
                source_windows,
            )
            connection.commit()
            source_windows = {}
            current_epoch = epoch

        src_ip = str(row["src_ip"])
        accumulator = source_windows.setdefault(src_ip, WindowAccumulator())
        accumulator.add(row)

    if current_epoch is not None:
        windows_created += _flush_window(
            connection,
            current_epoch,
            window_seconds,
            source_windows,
        )
        connection.commit()

    return windows_created


def _global_metric_baseline(
    connection: sqlite3.Connection,
    metric: str,
    window_seconds: int,
) -> RobustBaseline:
    if metric not in METRICS:
        raise ValueError(f"Unsupported metric: {metric}")

    count = connection.execute(
        "SELECT COUNT(*) FROM anomaly_windows WHERE window_seconds = ?",
        (window_seconds,),
    ).fetchone()[0]
    if count == 0:
        raise RuntimeError("No anomaly windows were created from the events table.")

    if count % 2:
        offsets = (count // 2,)
    else:
        offsets = (count // 2 - 1, count // 2)

    values = [
        float(
            connection.execute(
                f"""
                SELECT {metric}
                FROM anomaly_windows
                WHERE window_seconds = ?
                ORDER BY {metric}
                LIMIT 1 OFFSET ?
                """,
                (window_seconds, offset),
            ).fetchone()[0]
        )
        for offset in offsets
    ]
    center = sum(values) / len(values)

    if count % 2:
        mad_offsets = (count // 2,)
    else:
        mad_offsets = (count // 2 - 1, count // 2)

    deviations = [
        float(
            connection.execute(
                f"""
                SELECT ABS({metric} - ?) AS deviation
                FROM anomaly_windows
                WHERE window_seconds = ?
                ORDER BY deviation
                LIMIT 1 OFFSET ?
                """,
                (center, window_seconds, offset),
            ).fetchone()[0]
        )
        for offset in mad_offsets
    ]
    mad = sum(deviations) / len(deviations)
    return RobustBaseline(center, mad, int(count))


def calculate_baselines(
    connection: sqlite3.Connection,
    window_seconds: int,
    min_source_windows: int,
) -> int:
    if min_source_windows < 2:
        raise ValueError("min_source_windows must be at least 2")

    connection.execute(
        "DELETE FROM anomaly_baselines WHERE window_seconds = ?",
        (window_seconds,),
    )

    inserted = 0
    global_baselines: dict[str, RobustBaseline] = {}

    for metric in METRICS:
        baseline = _global_metric_baseline(connection, metric, window_seconds)
        global_baselines[metric] = baseline
        connection.execute(
            """
            INSERT INTO anomaly_baselines (
                scope_type, scope_key, metric, window_seconds,
                median_value, mad_value, sample_count
            ) VALUES ('global', '', ?, ?, ?, ?, ?)
            """,
            (
                metric,
                window_seconds,
                baseline.median_value,
                baseline.mad_value,
                baseline.sample_count,
            ),
        )
        inserted += 1

    source_rows = connection.execute(
        """
        SELECT src_ip, COUNT(*) AS n
        FROM anomaly_windows
        WHERE window_seconds = ?
        GROUP BY src_ip
        HAVING COUNT(*) >= ?
        ORDER BY src_ip
        """,
        (window_seconds, min_source_windows),
    )

    for source_row in source_rows:
        src_ip = source_row["src_ip"]
        rows = connection.execute(
            """
            SELECT event_count, unique_destinations, unique_destination_ports,
                   unique_flows, alert_count
            FROM anomaly_windows
            WHERE window_seconds = ? AND src_ip = ?
            ORDER BY window_start
            """,
            (window_seconds, src_ip),
        ).fetchall()

        for metric in METRICS:
            baseline = median_absolute_deviation(row[metric] for row in rows)
            connection.execute(
                """
                INSERT INTO anomaly_baselines (
                    scope_type, scope_key, metric, window_seconds,
                    median_value, mad_value, sample_count
                ) VALUES ('source', ?, ?, ?, ?, ?, ?)
                """,
                (
                    src_ip,
                    metric,
                    window_seconds,
                    baseline.median_value,
                    baseline.mad_value,
                    baseline.sample_count,
                ),
            )
            inserted += 1

    connection.commit()
    return inserted


def _load_baselines(
    connection: sqlite3.Connection,
    window_seconds: int,
) -> tuple[dict[str, RobustBaseline], dict[tuple[str, str], RobustBaseline]]:
    global_baselines: dict[str, RobustBaseline] = {}
    source_baselines: dict[tuple[str, str], RobustBaseline] = {}

    for row in connection.execute(
        """
        SELECT scope_type, scope_key, metric, median_value, mad_value, sample_count
        FROM anomaly_baselines
        WHERE window_seconds = ?
        """,
        (window_seconds,),
    ):
        baseline = RobustBaseline(
            float(row["median_value"]),
            float(row["mad_value"]),
            int(row["sample_count"]),
        )
        if row["scope_type"] == "global":
            global_baselines[row["metric"]] = baseline
        else:
            source_baselines[(row["scope_key"], row["metric"])] = baseline

    return global_baselines, source_baselines


def _fallback_scale(
    selected: RobustBaseline,
    global_baseline: RobustBaseline,
) -> float:
    if selected.mad_value > 0:
        return selected.mad_value
    if global_baseline.mad_value > 0:
        return global_baseline.mad_value

    return max(1.0, abs(selected.median_value) * 0.10)


def _finding_id(
    src_ip: str,
    window_start: str,
    window_seconds: int,
    metric: str,
) -> str:
    identity = f"{DETECTOR_NAME}|{src_ip}|{window_start}|{window_seconds}|{metric}"
    digest = hashlib.sha1(identity.encode("utf-8")).hexdigest()[:12].upper()
    return f"ANOM-{digest}"


def score_windows(
    connection: sqlite3.Connection,
    window_seconds: int,
    threshold: float,
) -> int:
    if threshold <= 0:
        raise ValueError("threshold must be greater than zero")

    global_baselines, source_baselines = _load_baselines(connection, window_seconds)
    if not global_baselines:
        raise RuntimeError("No baselines found. Calculate baselines before scoring.")

    connection.execute(
        "DELETE FROM anomaly_findings WHERE detector_name = ? AND window_seconds = ?",
        (DETECTOR_NAME, window_seconds),
    )

    created_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    findings = []

    for window in connection.execute(
        """
        SELECT src_ip, window_start, window_end,
               event_count, unique_destinations, unique_destination_ports,
               unique_flows, alert_count
        FROM anomaly_windows
        WHERE window_seconds = ?
        ORDER BY window_start, src_ip
        """,
        (window_seconds,),
    ):
        src_ip = window["src_ip"]

        for metric in METRICS:
            observed = float(window[metric])
            global_baseline = global_baselines[metric]
            source_baseline = source_baselines.get((src_ip, metric))
            baseline = source_baseline or global_baseline
            scope = "source" if source_baseline else "global"

            fallback = _fallback_scale(baseline, global_baseline)
            score, scale_used = modified_z_score(
                observed,
                baseline.median_value,
                baseline.mad_value,
                fallback,
            )

            if score < threshold:
                continue

            findings.append(
                (
                    _finding_id(src_ip, window["window_start"], window_seconds, metric),
                    DETECTOR_NAME,
                    METHOD_NAME,
                    window_seconds,
                    window["window_start"],
                    window["window_end"],
                    src_ip,
                    metric,
                    observed,
                    baseline.median_value,
                    baseline.mad_value,
                    scale_used,
                    score,
                    threshold,
                    scope,
                    REASONS[metric],
                    "candidate_for_investigation",
                    created_at,
                )
            )

            if len(findings) >= BATCH_SIZE:
                _insert_findings(connection, findings)
                findings = []

    if findings:
        _insert_findings(connection, findings)

    connection.commit()
    return connection.execute(
        """
        SELECT COUNT(*)
        FROM anomaly_findings
        WHERE detector_name = ? AND window_seconds = ?
        """,
        (DETECTOR_NAME, window_seconds),
    ).fetchone()[0]


def _insert_findings(connection: sqlite3.Connection, rows: Iterable[tuple]) -> None:
    connection.executemany(
        """
        INSERT INTO anomaly_findings (
            finding_id, detector_name, method, window_seconds,
            window_start, window_end, src_ip, metric,
            observed_value, baseline_median, baseline_mad, scale_used,
            anomaly_score, threshold, baseline_scope, reason, status, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(finding_id) DO UPDATE SET
            observed_value = excluded.observed_value,
            baseline_median = excluded.baseline_median,
            baseline_mad = excluded.baseline_mad,
            scale_used = excluded.scale_used,
            anomaly_score = excluded.anomaly_score,
            threshold = excluded.threshold,
            baseline_scope = excluded.baseline_scope,
            reason = excluded.reason,
            status = excluded.status,
            created_at = excluded.created_at
        """,
        rows,
    )


def link_events_to_findings(
    connection: sqlite3.Connection,
    window_seconds: int,
) -> int:
    connection.execute(
        """
        DELETE FROM anomaly_events
        WHERE finding_id IN (
            SELECT finding_id
            FROM anomaly_findings
            WHERE detector_name = ? AND window_seconds = ?
        )
        """,
        (DETECTOR_NAME, window_seconds),
    )

    finding_map: dict[tuple[str, int], list[str]] = {}
    for row in connection.execute(
        """
        SELECT finding_id, src_ip, window_start
        FROM anomaly_findings
        WHERE detector_name = ? AND window_seconds = ?
        """,
        (DETECTOR_NAME, window_seconds),
    ):
        epoch = bucket_epoch(parse_timestamp(row["window_start"]), window_seconds)
        finding_map.setdefault((row["src_ip"], epoch), []).append(row["finding_id"])

    if not finding_map:
        connection.commit()
        return 0

    rows_to_insert: list[tuple[str, int, int | None]] = []
    inserted = 0

    for event in connection.execute(
        """
        SELECT id, ts, flow_id, src_ip
        FROM events
        WHERE ts IS NOT NULL AND src_ip IS NOT NULL
        ORDER BY id
        """
    ):
        try:
            epoch = bucket_epoch(parse_timestamp(event["ts"]), window_seconds)
        except (TypeError, ValueError):
            continue

        finding_ids = finding_map.get((str(event["src_ip"]), epoch))
        if not finding_ids:
            continue

        for finding_id in finding_ids:
            rows_to_insert.append((finding_id, int(event["id"]), event["flow_id"]))

        if len(rows_to_insert) >= BATCH_SIZE:
            inserted += insert_many(
                connection,
                """
                INSERT OR IGNORE INTO anomaly_events (finding_id, event_id, flow_id)
                VALUES (?, ?, ?)
                """,
                rows_to_insert,
            )
            rows_to_insert = []

    if rows_to_insert:
        inserted += insert_many(
            connection,
            """
            INSERT OR IGNORE INTO anomaly_events (finding_id, event_id, flow_id)
            VALUES (?, ?, ?)
            """,
            rows_to_insert,
        )

    connection.commit()
    return inserted


def _start_run(
    connection: sqlite3.Connection,
    run_id: str,
    started_at: str,
    window_seconds: int,
    threshold: float,
    min_source_windows: int,
) -> None:
    connection.execute(
        """
        INSERT INTO anomaly_runs (
            run_id, detector_name, method, started_at,
            window_seconds, threshold, min_source_windows
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            run_id,
            DETECTOR_NAME,
            METHOD_NAME,
            started_at,
            window_seconds,
            threshold,
            min_source_windows,
        ),
    )
    connection.commit()


def _finish_run(
    connection: sqlite3.Connection,
    result: AnalysisResult,
) -> None:
    connection.execute(
        """
        UPDATE anomaly_runs
        SET completed_at = ?,
            windows_created = ?,
            baselines_created = ?,
            findings_created = ?,
            event_links_created = ?
        WHERE run_id = ?
        """,
        (
            datetime.now(timezone.utc).isoformat(timespec="seconds"),
            result.windows_created,
            result.baselines_created,
            result.findings_created,
            result.event_links_created,
            result.run_id,
        ),
    )
    connection.commit()


def run_analysis(
    db_path: str | Path,
    window_seconds: int = DEFAULT_WINDOW_SECONDS,
    threshold: float = DEFAULT_THRESHOLD,
    min_source_windows: int = DEFAULT_MIN_SOURCE_WINDOWS,
) -> AnalysisResult:
    run_id = str(uuid.uuid4())
    started_at = datetime.now(timezone.utc).isoformat(timespec="seconds")

    with closing(connect(db_path)) as connection:
        validate_events_table(connection)
        create_anomaly_tables(connection)
        _start_run(
            connection,
            run_id,
            started_at,
            window_seconds,
            threshold,
            min_source_windows,
        )

        windows = build_windows(connection, window_seconds)
        baselines = calculate_baselines(
            connection,
            window_seconds,
            min_source_windows,
        )
        findings = score_windows(connection, window_seconds, threshold)
        links = link_events_to_findings(connection, window_seconds)

        result = AnalysisResult(
            run_id=run_id,
            windows_created=windows,
            baselines_created=baselines,
            findings_created=findings,
            event_links_created=links,
        )
        _finish_run(connection, result)
        return result


def print_top_findings(
    db_path: str | Path,
    window_seconds: int,
    limit: int,
) -> None:
    if limit <= 0:
        return

    with closing(connect(db_path)) as connection:
        rows = connection.execute(
            """
            SELECT finding_id, src_ip, window_start, metric,
                   observed_value, baseline_median,
                   anomaly_score, baseline_scope, reason
            FROM anomaly_findings
            WHERE detector_name = ? AND window_seconds = ?
            ORDER BY anomaly_score DESC
            LIMIT ?
            """,
            (DETECTOR_NAME, window_seconds, limit),
        ).fetchall()

    if not rows:
        print("No anomaly findings exceeded the configured threshold.")
        return

    print()
    print("Top anomaly findings")
    print("--------------------")
    for row in rows:
        print(
            f"{row['finding_id']} | {row['src_ip']} | {row['window_start']} | "
            f"{row['metric']}={row['observed_value']:.0f} | "
            f"baseline={row['baseline_median']:.2f} | "
            f"score={row['anomaly_score']:.2f} | {row['baseline_scope']} baseline"
        )
        print(f"  {row['reason']}")


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Detect statistical network-behaviour anomalies from the MITS SQLite events table."
        )
    )
    parser.add_argument(
        "--db",
        type=Path,
        default=Path("mits.db"),
        help="SQLite database created by DataInitialFiltering/ingest.py (default: mits.db)",
    )
    parser.add_argument(
        "--window-seconds",
        type=int,
        default=DEFAULT_WINDOW_SECONDS,
        help=f"fixed aggregation window in seconds (default: {DEFAULT_WINDOW_SECONDS})",
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=DEFAULT_THRESHOLD,
        help=f"modified z-score threshold (default: {DEFAULT_THRESHOLD})",
    )
    parser.add_argument(
        "--min-source-windows",
        type=int,
        default=DEFAULT_MIN_SOURCE_WINDOWS,
        help=(
            "minimum number of windows needed to build a source-specific baseline; "
            f"otherwise the global baseline is used (default: {DEFAULT_MIN_SOURCE_WINDOWS})"
        ),
    )
    parser.add_argument(
        "--top",
        type=int,
        default=10,
        help="print the N highest-scoring findings after the run (default: 10)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_arguments()
    if not args.db.is_file():
        print(f"Error: database not found: {args.db}", file=sys.stderr)
        return 1

    print("======================================")
    print("MITS STATISTICAL ANOMALY DETECTION")
    print("======================================")
    print(f"Database:                {args.db}")
    print(f"Window size:             {args.window_seconds} seconds")
    print(f"Method:                  Median + MAD modified z-score")
    print(f"Threshold:               {args.threshold}")
    print(f"Min source windows:      {args.min_source_windows}")
    print()

    try:
        result = run_analysis(
            args.db,
            window_seconds=args.window_seconds,
            threshold=args.threshold,
            min_source_windows=args.min_source_windows,
        )
    except (RuntimeError, ValueError, sqlite3.Error, OSError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1

    print("Analysis completed.")
    print(f"Windows created:         {result.windows_created:,}")
    print(f"Baselines stored:        {result.baselines_created:,}")
    print(f"Anomaly findings:        {result.findings_created:,}")
    print(f"Finding-event links:     {result.event_links_created:,}")
    print(f"Run ID:                  {result.run_id}")

    print_top_findings(args.db, args.window_seconds, args.top)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
