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

import numpy as np
import pandas as pd

try:
    from .database import (
        connect,
        create_anomaly_tables,
        insert_many,
        validate_events_table,
    )
    from .robust_stats import (
        MODIFIED_Z_FACTOR,
        RobustBaseline,
        median_absolute_deviation,
        modified_z_score,
    )
except ImportError:  # Allows: python AnomalyDetection/anomaly_detection.py
    from database import (  # type: ignore
        connect,
        create_anomaly_tables,
        insert_many,
        validate_events_table,
    )
    from robust_stats import (  # type: ignore
        MODIFIED_Z_FACTOR,
        RobustBaseline,
        median_absolute_deviation,
        modified_z_score,
    )

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

    This loads events in one bulk query and aggregates them with vectorized
    pandas/numpy operations, rather than streaming rows one at a time through
    a Python loop (parsing each timestamp individually via
    datetime.fromisoformat + astimezone, and committing once per window
    boundary). At millions of events, that per-row Python overhead -- and
    the SQLite commit-per-window pattern, which can mean thousands of
    commits for a dataset spanning more than a few hours -- was the actual
    cost, not anything algorithmically necessary about the aggregation
    itself. This keeps the exact same per-(source, window) metrics and the
    same upsert semantics, just computed and written in bulk.
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

    events = pd.read_sql_query(
        """
        SELECT ts, event_type, flow_id, src_ip, dest_ip, dest_port
        FROM events
        WHERE ts IS NOT NULL AND src_ip IS NOT NULL
        """,
        connection,
    )

    if events.empty:
        connection.commit()
        return 0

    # utc=True normalizes every row to UTC regardless of its own offset in
    # one vectorized pass (this project's eve.json timestamps carry mixed
    # offsets -- confirmed earlier), and malformed timestamps become NaT
    # (errors="coerce") rather than raising, matching the original's
    # per-row try/except skip.
    timestamps = pd.to_datetime(events["ts"], utc=True, errors="coerce")
    valid = timestamps.notna()
    events = events.loc[valid].copy()
    timestamps = timestamps.loc[valid]

    if events.empty:
        connection.commit()
        return 0

    # Resolution-independent: pandas may store parsed timestamps at
    # microsecond or nanosecond resolution depending on version/build (
    # confirmed: this environment's pd.to_datetime(..., utc=True) produces
    # datetime64[us], not [ns]) -- dividing a raw .astype("int64") result
    # by a fixed 1_000_000_000 silently assumes nanoseconds and is wrong
    # (by exactly that factor) whenever the actual resolution differs, as
    # it did here. Computing whole seconds via Timedelta floor-division
    # instead works correctly regardless of the underlying resolution.
    unix_epoch = pd.Timestamp("1970-01-01", tz="UTC")
    epoch_seconds = ((timestamps - unix_epoch) // pd.Timedelta(seconds=1)).to_numpy()
    events["window_epoch"] = (epoch_seconds // window_seconds) * window_seconds
    events["src_ip"] = events["src_ip"].astype(str)

    # Match WindowAccumulator.add()'s "if row["dest_ip"]:" truthiness check
    # (which also excludes empty strings, not just None/NaN) before
    # counting distinct destinations -- pandas' nunique() only excludes
    # NaN by default.
    dest_ip = events["dest_ip"].replace("", pd.NA)

    grouped = events.groupby(["src_ip", "window_epoch"], sort=False)
    aggregated = grouped.agg(
        event_count=("src_ip", "size"),
        unique_destination_ports=("dest_port", "nunique"),
        unique_flows=("flow_id", "nunique"),
        alert_count=("event_type", lambda s: int((s == "alert").sum())),
    )
    aggregated["unique_destinations"] = (
        dest_ip.groupby([events["src_ip"], events["window_epoch"]], sort=False).nunique()
    )
    aggregated = aggregated.reset_index()

    aggregated["window_start"] = aggregated["window_epoch"].map(
        lambda epoch: epoch_to_iso(int(epoch))
    )
    aggregated["window_end"] = aggregated["window_epoch"].map(
        lambda epoch: epoch_to_iso(int(epoch) + window_seconds)
    )

    rows = list(
        zip(
            aggregated["src_ip"],
            aggregated["window_start"],
            aggregated["window_end"],
            [window_seconds] * len(aggregated),
            aggregated["event_count"].astype(int),
            aggregated["unique_destinations"].astype(int),
            aggregated["unique_destination_ports"].astype(int),
            aggregated["unique_flows"].astype(int),
            aggregated["alert_count"].astype(int),
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
    connection.commit()
    return len(rows)


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
    """Compute global and per-source median/MAD baselines for every metric.

    The original queried each metric's median/MAD via repeated `ORDER BY
    metric LIMIT 1 OFFSET n` SQL statements (effectively re-sorting the
    whole anomaly_windows table once per metric per statistic), and
    separately issued one SQL query *per qualifying source* plus a
    pure-Python median/MAD call per source per metric. With thousands of
    sources that's thousands of round trips and thousands of small Python
    computations. This loads anomaly_windows once and computes every
    median/MAD -- global and per-source, every metric at once -- via
    vectorized pandas groupby/transform calls instead.
    """
    if min_source_windows < 2:
        raise ValueError("min_source_windows must be at least 2")

    connection.execute(
        "DELETE FROM anomaly_baselines WHERE window_seconds = ?",
        (window_seconds,),
    )

    metric_columns = list(METRICS)
    windows_df = pd.read_sql_query(
        f"""
        SELECT src_ip, {", ".join(metric_columns)}
        FROM anomaly_windows
        WHERE window_seconds = ?
        """,
        connection,
        params=(window_seconds,),
    )

    if windows_df.empty:
        raise RuntimeError("No anomaly windows were created from the events table.")

    for metric in metric_columns:
        windows_df[metric] = windows_df[metric].astype(float)

    rows = []

    # Global baselines: one median/MAD per metric across every window,
    # regardless of source.
    for metric in metric_columns:
        values = windows_df[metric].to_numpy()
        median_value = float(np.median(values))
        mad_value = float(np.median(np.abs(values - median_value)))
        rows.append(
            ("global", "", metric, window_seconds, median_value, mad_value, len(values))
        )

    # Per-source baselines, only for sources with enough windows of their
    # own. median/MAD for every (source, metric) pair computed via two
    # vectorized groupby passes (median, then MAD from that median) rather
    # than a per-source Python loop.
    source_counts = windows_df.groupby("src_ip", sort=False).size()
    qualifying_sources = source_counts[source_counts >= min_source_windows].index

    if len(qualifying_sources):
        qualifying_df = windows_df[windows_df["src_ip"].isin(qualifying_sources)]

        source_medians = qualifying_df.groupby("src_ip", sort=False)[metric_columns].median()
        medians_broadcast = qualifying_df.groupby("src_ip", sort=False)[metric_columns].transform(
            "median"
        )
        abs_deviation = (qualifying_df[metric_columns] - medians_broadcast).abs()
        abs_deviation["src_ip"] = qualifying_df["src_ip"]
        source_mads = abs_deviation.groupby("src_ip", sort=False)[metric_columns].median()
        source_sample_counts = qualifying_df.groupby("src_ip", sort=False).size()

        # Reshape wide (one column per metric) to long (one row per
        # source+metric) and join the three pieces together, instead of a
        # nested Python loop doing repeated .loc[] lookups -- with
        # thousands of qualifying sources x 5 metrics, that lookup-per-cell
        # pattern would itself become the next bottleneck.
        medians_long = (
            source_medians.reset_index()
            .melt(id_vars="src_ip", var_name="metric", value_name="median_value")
        )
        mads_long = (
            source_mads.reset_index()
            .melt(id_vars="src_ip", var_name="metric", value_name="mad_value")
        )
        counts_df = source_sample_counts.reset_index(name="sample_count")

        combined = medians_long.merge(mads_long, on=["src_ip", "metric"]).merge(
            counts_df, on="src_ip"
        )
        combined = combined.sort_values(["src_ip", "metric"])

        for src_ip, metric, median_value, mad_value, sample_count in zip(
            combined["src_ip"],
            combined["metric"],
            combined["median_value"],
            combined["mad_value"],
            combined["sample_count"],
        ):
            rows.append(
                (
                    "source",
                    src_ip,
                    metric,
                    window_seconds,
                    float(median_value),
                    float(mad_value),
                    int(sample_count),
                )
            )

    connection.executemany(
        """
        INSERT INTO anomaly_baselines (
            scope_type, scope_key, metric, window_seconds,
            median_value, mad_value, sample_count
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        rows,
    )
    connection.commit()
    return len(rows)


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
    """Score every window against its baseline for every metric.

    The original streamed every window via a cursor and scored its 5
    metrics with pure-Python arithmetic per window -- correct, but with
    hundreds of thousands of windows that's millions of individual
    modified_z_score() calls. This loads all windows once and scores every
    metric for every window in one vectorized pass per metric (5 passes
    total, not one per window), replicating _fallback_scale's and
    modified_z_score's exact branching with numpy.where instead of a
    Python if/else per call.
    """
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

    metric_columns = list(METRICS)
    windows_df = pd.read_sql_query(
        f"""
        SELECT src_ip, window_start, window_end, {", ".join(metric_columns)}
        FROM anomaly_windows
        WHERE window_seconds = ?
        ORDER BY window_start, src_ip
        """,
        connection,
        params=(window_seconds,),
    )

    if windows_df.empty:
        connection.commit()
        return 0

    all_findings = []

    for metric in metric_columns:
        observed = windows_df[metric].astype(float).to_numpy()
        global_baseline = global_baselines[metric]
        global_median = global_baseline.median_value
        global_mad = global_baseline.mad_value

        # Per-row selected baseline: this source's own baseline for this
        # metric if it has one, else the global one -- built via a vectorized
        # .map() instead of a per-row dict .get().
        source_median_map = {
            src: b.median_value for (src, m), b in source_baselines.items() if m == metric
        }
        source_mad_map = {
            src: b.mad_value for (src, m), b in source_baselines.items() if m == metric
        }

        has_source_baseline = windows_df["src_ip"].isin(source_median_map.keys()).to_numpy()
        selected_median = windows_df["src_ip"].map(source_median_map).fillna(global_median).to_numpy()
        selected_mad = windows_df["src_ip"].map(source_mad_map).fillna(global_mad).to_numpy()

        # _fallback_scale: selected mad if >0, else global mad if >0, else
        # max(1.0, abs(selected median) * 0.10).
        fallback = np.where(
            selected_mad > 0,
            selected_mad,
            np.where(
                global_mad > 0,
                global_mad,
                np.maximum(1.0, np.abs(selected_median) * 0.10),
            ),
        )

        # modified_z_score's exact branching, vectorized:
        below_or_equal = observed <= selected_median
        base_scale = np.where(selected_mad > 0, selected_mad, fallback)
        # Branch 1 (observed <= median): scale_used = base_scale, unclamped.
        # Branch 2 (observed > median): scale is clamped to 1.0 if <= 0
        # before being used for both the score and the returned scale_used.
        clamped_scale = np.where(base_scale <= 0, 1.0, base_scale)
        scale_used = np.where(below_or_equal, base_scale, clamped_scale)
        score = np.where(
            below_or_equal,
            0.0,
            MODIFIED_Z_FACTOR * (observed - selected_median) / clamped_scale,
        )

        qualifying = np.flatnonzero(score >= threshold)
        if len(qualifying) == 0:
            continue

        scope = np.where(has_source_baseline, "source", "global")
        reason = REASONS[metric]

        for i in qualifying:
            src_ip = windows_df["src_ip"].iat[i]
            window_start = windows_df["window_start"].iat[i]
            all_findings.append(
                (
                    _finding_id(src_ip, window_start, window_seconds, metric),
                    DETECTOR_NAME,
                    METHOD_NAME,
                    window_seconds,
                    window_start,
                    windows_df["window_end"].iat[i],
                    src_ip,
                    metric,
                    float(observed[i]),
                    float(selected_median[i]),
                    float(selected_mad[i]),
                    float(scale_used[i]),
                    float(score[i]),
                    threshold,
                    scope[i],
                    reason,
                    "candidate_for_investigation",
                    created_at,
                )
            )

    for start in range(0, len(all_findings), BATCH_SIZE):
        _insert_findings(connection, all_findings[start:start + BATCH_SIZE])

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
    """Link each finding back to the events that fed its window.

    The original re-parsed every event's timestamp a *second* time here
    (build_windows already parsed all of them once) via the same
    per-row datetime.fromisoformat + astimezone call, just to recompute
    the same (source, window) bucket and look it up in a Python dict. At
    millions of events that duplicate parsing pass was pure waste. This
    parses timestamps once (vectorized), then finds matching events via a
    single pandas merge (a vectorized join) instead of a per-event dict
    lookup.
    """
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

    findings_df = pd.read_sql_query(
        """
        SELECT finding_id, src_ip, window_start
        FROM anomaly_findings
        WHERE detector_name = ? AND window_seconds = ?
        """,
        connection,
        params=(DETECTOR_NAME, window_seconds),
    )

    if findings_df.empty:
        connection.commit()
        return 0

    unix_epoch = pd.Timestamp("1970-01-01", tz="UTC")
    window_start_ts = pd.to_datetime(findings_df["window_start"], utc=True, errors="coerce")
    # Resolution-independent epoch computation -- see build_windows for why
    # a raw .astype("int64") // 1_000_000_000 is unsafe here.
    findings_df["epoch"] = (
        ((window_start_ts - unix_epoch) // pd.Timedelta(seconds=1)) // window_seconds
    ) * window_seconds

    events_df = pd.read_sql_query(
        """
        SELECT id, ts, flow_id, src_ip
        FROM events
        WHERE ts IS NOT NULL AND src_ip IS NOT NULL
        """,
        connection,
    )

    if events_df.empty:
        connection.commit()
        return 0

    event_ts = pd.to_datetime(events_df["ts"], utc=True, errors="coerce")
    valid = event_ts.notna()
    events_df = events_df.loc[valid].copy()
    event_ts = event_ts.loc[valid]
    events_df["src_ip"] = events_df["src_ip"].astype(str)
    events_df["epoch"] = (
        ((event_ts - unix_epoch) // pd.Timedelta(seconds=1)) // window_seconds
    ) * window_seconds

    merged = events_df.merge(
        findings_df[["finding_id", "src_ip", "epoch"]],
        on=["src_ip", "epoch"],
        how="inner",
    )

    if merged.empty:
        connection.commit()
        return 0

    flow_ids = [None if pd.isna(v) else int(v) for v in merged["flow_id"]]
    rows_to_insert = list(zip(merged["finding_id"], merged["id"].astype(int), flow_ids))

    inserted = 0
    for start in range(0, len(rows_to_insert), BATCH_SIZE):
        inserted += insert_many(
            connection,
            """
            INSERT OR IGNORE INTO anomaly_events (finding_id, event_id, flow_id)
            VALUES (?, ?, ?)
            """,
            rows_to_insert[start:start + BATCH_SIZE],
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