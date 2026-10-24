import csv
import json
import math
import os
import sqlite3
from bisect import bisect_left, bisect_right
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

from analysis.case_correlation import (
    build_candidate_cases,
    get_destinations,
    get_finding_id,
    get_flow_ids,
    get_ports,
)
from analysis.correlation import (
    DATABASE_FILE,
    build_sessions,
    create_sessions,
    group_flows,
    load_flows,
)
from analysis.detection import (
    build_high_connection_findings,
    build_multi_port_findings,
    build_protocol_anomaly_findings,
    detect_repeated_failed_authentication,
    load_events,
)


MODEL_RANDOM_STATE = 42
MODEL_ESTIMATORS = 300
MAX_TRAINING_CASES = 50_000
SCORING_BATCH_SIZE = 10_000
PRINT_CASE_LIMIT = 25
INCLUDE_CASE_FEATURES = os.getenv(
    "MITS_INCLUDE_CASE_FEATURES", "1"
).lower() not in {"0", "false", "no"}
OUTPUT_DIRECTORY = (
    Path(__file__).resolve().parent.parent / "output"
)


def to_utc_timestamp(value):
    timestamp = pd.Timestamp(value)

    if timestamp.tzinfo is None:
        return timestamp.tz_localize("UTC")

    return timestamp.tz_convert("UTC")


def create_findings():
    events = load_events()
    findings = []

    # Extend the same result list instead of repeatedly copying findings.
    detection_functions = (
        build_high_connection_findings,
        build_multi_port_findings,
        detect_repeated_failed_authentication,
        build_protocol_anomaly_findings,
    )

    for detect in detection_functions:
        findings.extend(detect(events))

    for index, finding in enumerate(findings, start=1):
        if "finding_id" not in finding:
            finding["finding_id"] = get_finding_id(finding, index)

    return findings


def create_network_sessions():
    if not DATABASE_FILE.exists():
        return []

    with sqlite3.connect(DATABASE_FILE) as connection:
        flows = load_flows(connection)
        flow_groups = group_flows(flows)
        raw_sessions = create_sessions(flow_groups)
        return build_sessions(raw_sessions)


def get_case_findings(case, finding_lookup):
    return [
        finding_lookup[finding_id]
        for finding_id in case.get("finding_ids", [])
        if finding_id in finding_lookup
    ]


class SessionIndex:
    """Match sessions by source IP and overlapping time intervals.

    A sorted index avoids scanning and parsing every session for every case.
    """

    def __init__(self, sessions):
        grouped = defaultdict(list)

        for session in sessions:
            grouped[session.get("src_ip")].append((
                to_utc_timestamp(session["first_seen"]).value,
                to_utc_timestamp(session["last_seen"]).value,
                session.get("dest_ip"),
                session,
            ))

        self.by_source = {}

        for source_ip, entries in grouped.items():
            entries.sort(key=lambda item: item[0])
            starts = []
            maximum_ends = []

            for session_start, session_end, _, _ in entries:
                starts.append(session_start)
                maximum_ends.append(
                    max(maximum_ends[-1], session_end)
                    if maximum_ends
                    else session_end
                )

            self.by_source[source_ip] = (
                entries,
                starts,
                maximum_ends,
            )

    def iter_matches(self, case):
        """Yield sessions overlapping the case without a full-table scan."""
        case_start = to_utc_timestamp(case["first_seen"]).value
        case_end = to_utc_timestamp(case["last_seen"]).value
        destinations = set(case.get("destination_ips", []))

        for source_ip in set(case.get("source_ips", [])):
            bucket = self.by_source.get(source_ip)
            if bucket is None:
                continue

            entries, starts, maximum_ends = bucket
            first = bisect_left(maximum_ends, case_start)
            last = bisect_right(starts, case_end)

            for position in range(first, last):
                _, session_end, destination_ip, session = entries[position]
                if session_end < case_start:
                    continue
                if destinations and destination_ip not in destinations:
                    continue
                yield session


def get_matching_sessions(case, sessions):
    """Return matching sessions, retaining the original public interface."""
    session_index = (
        sessions
        if isinstance(sessions, SessionIndex)
        else SessionIndex(sessions)
    )
    return list(session_index.iter_matches(case))


def add_time_features(features, prefix, timestamp):
    timestamp = to_utc_timestamp(timestamp)

    hour = (
        timestamp.hour
        + timestamp.minute / 60
        + timestamp.second / 3600
    )

    angle = 2 * math.pi * hour / 24

    features[f"{prefix}_hour_sin"] = math.sin(angle)
    features[f"{prefix}_hour_cos"] = math.cos(angle)


def add_counter_features(features, prefix, values):
    counts = Counter(values)

    for value, count in counts.items():
        safe_value = (
            str(value)
            .strip()
            .lower()
            .replace(" ", "_")
            .replace("-", "_")
            .replace("/", "_")
        )

        features[
            f"{prefix}_{safe_value}_count"
        ] = float(count)


def collect_numeric_values(
    value,
    prefix,
    collected,
):
    if isinstance(value, bool):
        collected[prefix].append(float(value))
        return

    if isinstance(value, (int, float, np.integer, np.floating)):
        if math.isfinite(float(value)):
            collected[prefix].append(float(value))
        return

    if isinstance(value, dict):
        for key, nested_value in value.items():
            key_text = str(key).lower()

            if (
                key_text.endswith("_id")
                or key_text.endswith("_ids")
                or "timestamp" in key_text
                or key_text in {
                    "src_ip",
                    "source_ip",
                    "dest_ip",
                    "destination_ip",
                }
            ):
                continue

            nested_prefix = (
                f"{prefix}_{key}"
                if prefix
                else str(key)
            )

            collect_numeric_values(
                nested_value,
                nested_prefix,
                collected,
            )

        return

    if isinstance(value, (list, tuple, set)):
        collected[f"{prefix}_length"].append(
            float(len(value))
        )

        key_text = prefix.lower()

        if (
            key_text.endswith("_ids")
            or "flow_id" in key_text
            or "port" in key_text
        ):
            return

        for nested_value in value:
            collect_numeric_values(
                nested_value,
                prefix,
                collected,
            )


def add_finding_numeric_features(
    features,
    case_findings,
):
    collected = defaultdict(list)

    for finding in case_findings:
        for key, value in finding.items():
            if key in {
                "finding_id",
                "rule_id",
                "timestamp",
                "source_ip",
                "flow_ids",
            }:
                continue

            collect_numeric_values(
                value,
                str(key),
                collected,
            )

    for key, values in collected.items():
        if not values:
            continue

        features[f"finding_{key}_sum"] = float(
            sum(values)
        )
        features[f"finding_{key}_mean"] = float(
            sum(values) / len(values)
        )
        features[f"finding_{key}_max"] = float(
            max(values)
        )


def build_case_features(
    case,
    finding_lookup,
    sessions,
):
    case_findings = get_case_findings(
        case,
        finding_lookup,
    )

    case_start = to_utc_timestamp(
        case["first_seen"]
    )
    case_end = to_utc_timestamp(
        case["last_seen"]
    )

    duration_seconds = max(
        0.0,
        (case_end - case_start).total_seconds(),
    )

    rule_ids = [
        finding.get("rule_id")
        for finding in case_findings
        if finding.get("rule_id")
    ]

    source_ips = set(
        case.get("source_ips", [])
    )
    destination_ips = set(
        case.get("destination_ips", [])
    )

    flow_ids = set()
    destination_ports = set()
    finding_destination_ips = set()

    findings_with_flows = 0
    findings_with_ports = 0

    for finding in case_findings:
        finding_flows = get_flow_ids(finding)
        finding_ports = get_ports(finding)
        finding_destinations = get_destinations(
            finding
        )

        if finding_flows:
            findings_with_flows += 1

        if finding_ports:
            findings_with_ports += 1

        flow_ids.update(finding_flows)
        destination_ports.update(finding_ports)
        finding_destination_ips.update(
            finding_destinations
        )

    features = {
        "finding_count": float(
            case.get(
                "finding_count",
                len(case_findings),
            )
        ),
        "unique_rule_count": float(
            len(set(rule_ids))
        ),
        "source_ip_count": float(
            len(source_ips)
        ),
        "destination_ip_count": float(
            len(destination_ips)
        ),
        "finding_destination_ip_count": float(
            len(finding_destination_ips)
        ),
        "unique_flow_id_count": float(
            len(flow_ids)
        ),
        "unique_destination_port_count": float(
            len(destination_ports)
        ),
        "findings_with_flow_ids": float(
            findings_with_flows
        ),
        "findings_with_destination_ports": float(
            findings_with_ports
        ),
        "case_duration_seconds": float(
            duration_seconds
        ),
        "correlation_reason_count": float(
            len(
                case.get(
                    "correlation_reasons",
                    [],
                )
            )
        ),
    }

    add_time_features(
        features,
        "case_start",
        case_start,
    )
    add_time_features(
        features,
        "case_end",
        case_end,
    )

    correlation_strength = (
        case.get(
            "correlation_strength",
            "Unknown",
        )
    )

    add_counter_features(
        features,
        "correlation_strength",
        [correlation_strength],
    )

    add_counter_features(
        features,
        "rule",
        rule_ids,
    )

    add_counter_features(
        features,
        "correlation_reason",
        case.get(
            "correlation_reasons",
            [],
        ),
    )

    add_finding_numeric_features(
        features,
        case_findings,
    )

    session_index = (
        sessions
        if isinstance(sessions, SessionIndex)
        else SessionIndex(sessions)
    )

    session_flow_ids = set()
    session_destination_ports = set()
    session_source_ports = set()
    session_protocols = []
    session_durations = []

    total_session_flows = 0
    total_session_events = 0
    matched_session_count = 0

    for session in session_index.iter_matches(case):
        matched_session_count += 1
        total_session_flows += int(
            session.get("flow_count", 0)
        )
        total_session_events += int(
            session.get("event_count", 0)
        )

        session_flow_ids.update(
            session.get("flow_ids", [])
        )
        session_destination_ports.update(
            session.get(
                "destination_ports",
                [],
            )
        )
        session_source_ports.update(
            session.get(
                "source_ports",
                [],
            )
        )

        protocol = session.get("protocol")

        if protocol:
            session_protocols.append(protocol)

        session_durations.append(
            float(
                session.get(
                    "duration_seconds",
                    0,
                )
            )
        )

    features.update({
        "matched_session_count": float(
            matched_session_count
        ),
        "session_total_flow_count": float(
            total_session_flows
        ),
        "session_total_event_count": float(
            total_session_events
        ),
        "session_unique_flow_id_count": float(
            len(session_flow_ids)
        ),
        "session_unique_destination_port_count": float(
            len(session_destination_ports)
        ),
        "session_unique_source_port_count": float(
            len(session_source_ports)
        ),
        "session_unique_protocol_count": float(
            len(set(session_protocols))
        ),
        "session_duration_total_seconds": float(
            sum(session_durations)
        ),
        "session_duration_mean_seconds": float(
            np.mean(session_durations)
            if session_durations
            else 0.0
        ),
        "session_duration_max_seconds": float(
            max(session_durations)
            if session_durations
            else 0.0
        ),
    })

    add_counter_features(
        features,
        "session_protocol",
        session_protocols,
    )

    return features


def build_feature_matrix(
    cases,
    findings,
    sessions,
):
    finding_lookup = {
        finding["finding_id"]: finding
        for finding in findings
        if "finding_id" in finding
    }

    # Build this once, not once per case.
    session_index = SessionIndex(sessions)
    rows = [
        build_case_features(case, finding_lookup, session_index)
        for case in cases
    ]

    feature_frame = pd.DataFrame(
        rows,
        index=[case["case_id"] for case in cases],
    )
    rows.clear()

    # IsolationForest operates on float32, so do not retain float64 values.
    feature_frame = feature_frame.astype(np.float32, copy=False)
    feature_frame.replace([np.inf, -np.inf], 0.0, inplace=True)
    feature_frame.fillna(0.0, inplace=True)

    # Min/max avoids repeated per-column cardinality calculations.
    minimums = feature_frame.min(axis=0)
    maximums = feature_frame.max(axis=0)
    variable_columns = feature_frame.columns[
        minimums.ne(maximums)
    ].tolist()

    return feature_frame, variable_columns


def calculate_priority(
    cases,
    feature_frame,
    variable_columns,
):
    prioritized_cases = [case.copy() for case in cases]
    if not prioritized_cases:
        return []

    feature_names = feature_frame.columns.tolist()

    if not variable_columns:
        for index, (case, feature_values) in enumerate(
            zip(
                prioritized_cases,
                feature_frame.itertuples(index=False, name=None),
            ),
            start=1,
        ):
            case["priority_rank"] = index
            case["priority_score"] = 50.0
            case["isolation_forest_score"] = 0.0
            case["isolation_forest_classification"] = "Undetermined"
            if INCLUDE_CASE_FEATURES:
                case["priority_features"] = dict(
                    zip(feature_names, map(float, feature_values))
                )
        return prioritized_cases

    # Use a numeric array to avoid the overhead of converting Pandas input.
    model_data = feature_frame[variable_columns].to_numpy(
        dtype=np.float32,
        copy=False,
    )
    training_data = model_data

    # Limit training memory while still scoring every candidate case.
    if len(model_data) > MAX_TRAINING_CASES:
        rng = np.random.default_rng(MODEL_RANDOM_STATE)
        training_indices = rng.choice(
            len(model_data),
            size=MAX_TRAINING_CASES,
            replace=False,
        )
        training_data = model_data[training_indices]

    model = IsolationForest(
        n_estimators=MODEL_ESTIMATORS,
        contamination="auto",
        random_state=MODEL_RANDOM_STATE,
        n_jobs=-1,
    )
    model.fit(training_data)

    # Score in batches to bound temporary allocations on large datasets.
    raw_scores = np.empty(len(model_data), dtype=np.float64)
    for start in range(0, len(model_data), SCORING_BATCH_SIZE):
        stop = min(start + SCORING_BATCH_SIZE, len(model_data))
        raw_scores[start:stop] = -model.score_samples(
            model_data[start:stop]
        )

    # predict() would run score_samples() a second time.
    predictions = np.where(-raw_scores < model.offset_, -1, 1)
    percentile_scores = (
        pd.Series(raw_scores)
        .rank(method="average", pct=True)
        .to_numpy()
        * 100
    )

    for case, score, percentile, prediction, feature_values in zip(
        prioritized_cases,
        raw_scores,
        percentile_scores,
        predictions,
        feature_frame.itertuples(index=False, name=None),
    ):
        case["priority_score"] = round(float(percentile), 2)
        case["isolation_forest_score"] = round(float(score), 6)
        case["isolation_forest_classification"] = (
            "Anomaly" if prediction == -1 else "Normal"
        )
        if INCLUDE_CASE_FEATURES:
            case["priority_features"] = dict(
                zip(feature_names, map(float, feature_values))
            )

    prioritized_cases.sort(
        key=lambda case: (
            -case["priority_score"],
            -case["isolation_forest_score"],
            to_utc_timestamp(case["first_seen"]),
        )
    )

    for rank, case in enumerate(prioritized_cases, start=1):
        case["priority_rank"] = rank

    return prioritized_cases


def prioritize_cases(
    cases,
    findings,
    sessions=None,
):
    if sessions is None:
        sessions = []

    feature_frame, variable_columns = (
        build_feature_matrix(
            cases,
            findings,
            sessions,
        )
    )

    prioritized_cases = calculate_priority(
        cases,
        feature_frame,
        variable_columns,
    )

    return (
        prioritized_cases,
        feature_frame,
        variable_columns,
    )


def json_default(value):
    if isinstance(
        value,
        (
            pd.Timestamp,
            np.integer,
            np.floating,
        ),
    ):
        if isinstance(value, pd.Timestamp):
            return value.isoformat()

        return value.item()

    if isinstance(value, set):
        return sorted(value)

    raise TypeError(
        f"Object of type "
        f"{type(value).__name__} "
        f"is not JSON serializable"
    )


def save_results(
    prioritized_cases,
    feature_frame,
):
    OUTPUT_DIRECTORY.mkdir(
        parents=True,
        exist_ok=True,
    )

    json_path = (
        OUTPUT_DIRECTORY
        / "prioritized_cases_v3.json"
    )
    csv_path = (
        OUTPUT_DIRECTORY
        / "prioritized_cases_v3.csv"
    )
    feature_path = (
        OUTPUT_DIRECTORY
        / "prioritization_features_v3.csv"
    )

    with json_path.open(
        "w",
        encoding="utf-8",
    ) as output_file:
        json.dump(
            prioritized_cases,
            output_file,
            indent=2,
            default=json_default,
        )

    # Stream CSV rows instead of building a second in-memory DataFrame.
    with csv_path.open("w", encoding="utf-8", newline="") as csv_file:
        csv_writer = csv.writer(csv_file)
        csv_writer.writerow([
            "priority_rank", "case_id", "priority_score",
            "isolation_forest_score", "classification", "first_seen",
            "last_seen", "finding_count", "rule_ids", "source_ips",
            "destination_ips",
        ])

        for case in prioritized_cases:
            csv_writer.writerow([
                case["priority_rank"],
                case["case_id"],
                case["priority_score"],
                case["isolation_forest_score"],
                case["isolation_forest_classification"],
                case["first_seen"],
                case["last_seen"],
                case["finding_count"],
                ",".join(case.get("rule_ids", [])),
                ",".join(case.get("source_ips", [])),
                ",".join(case.get("destination_ips", [])),
            ])

    feature_frame.to_csv(
        feature_path,
        index_label="case_id",
    )

    return (
        json_path,
        csv_path,
        feature_path,
    )


def print_results(
    prioritized_cases,
    variable_columns,
):
    print()
    print("=" * 100)
    print("ISOLATION FOREST CASE PRIORITIZATION")
    print("=" * 100)
    print(
        f"Cases analyzed: "
        f"{len(prioritized_cases)}"
    )
    print(
        f"Features used by model: "
        f"{len(variable_columns)}"
    )

    if len(prioritized_cases) < 10:
        print(
            "Warning: very few cases are available. "
            "The model can run, but the ranking "
            "has limited statistical context."
        )

    print()
    print(
        "Rank | Case ID   | Priority | "
        "IF score | Classification | Findings"
    )
    print("-" * 100)

    for case in prioritized_cases[:PRINT_CASE_LIMIT]:
        print(
            f"{case['priority_rank']:>4} | "
            f"{case['case_id']:<9} | "
            f"{case['priority_score']:>8.2f} | "
            f"{case['isolation_forest_score']:>8.6f} | "
            f"{case['isolation_forest_classification']:<14} | "
            f"{case['finding_count']}"
        )

    if len(prioritized_cases) > PRINT_CASE_LIMIT:
        print(
            f"Showing top {PRINT_CASE_LIMIT} of "
            f"{len(prioritized_cases)} cases. Full results are in CSV/JSON."
        )



_v2_create_findings = create_findings

# ---------------------------------------------------------------------------
# V3 detection: process relevant SQLite rows without loading all events.
# The input database is read-only and the existing detection rule IDs,
# threshold values, and output structure are preserved.
# ---------------------------------------------------------------------------
from functools import lru_cache
from itertools import groupby
from time import perf_counter
import json as _json

from analysis import detection as _det

OUTPUT_DIRECTORY = Path(__file__).resolve().parent.parent / 'output'
MODEL_ESTIMATORS = int(os.getenv('MITS_V3_TREES', '100'))
MAX_TRAINING_CASES = int(os.getenv('MITS_V3_MAX_TRAINING_CASES', '50000'))
INCLUDE_CASE_FEATURES = os.getenv('MITS_INCLUDE_CASE_FEATURES', '0').lower() not in {'0','false','no'}


def _open_events_readonly():
    """Access the event database without modifying it."""
    path = _det.DATABASE_PATH.resolve()
    if not path.is_file():
        raise FileNotFoundError(f'Event database not found: {path}')
    connection = sqlite3.connect(path.as_uri() + '?mode=ro', uri=True)
    connection.execute('PRAGMA temp_store = FILE')
    connection.execute('PRAGMA cache_size = -32768')
    connection.create_function('mits_v3_internal_ip', 1, _is_internal_ip)
    return connection


@lru_cache(maxsize=131072)
def _is_internal_ip(ip):
    return int(_det.is_internal_ip(ip))


def _group_rows(cursor, source_column):
    """Read one source-IP group at a time, not the entire SQLite result."""
    for source_ip, rows in groupby(cursor, key=lambda row: row[source_column]):
        yield source_ip, list(rows)


def _window_bounds(rows, timestamp_column, seconds):
    """Compute inclusive rolling-window endpoints with binary search."""
    stamps = pd.to_datetime(
        [row[timestamp_column] for row in rows],
        utc=True,
        errors='coerce',
        format='mixed',
    )
    # SQL ORDER BY ts is chronological for normalized ISO timestamps from EVE.
    # Sorting again handles offset differences and unexpected timestamp layouts.
    order = np.argsort(stamps.asi8, kind='stable')
    if not np.array_equal(order, np.arange(len(rows))):
        rows = [rows[i] for i in order]
        stamps = stamps.take(order)
    ns = stamps.asi8
    valid_count = np.searchsorted(ns, np.iinfo(np.int64).max - seconds * 1_000_000_000)
    # Avoid a Nanosecond overflow when computing the inclusive end.
    maximum = np.iinfo(np.int64).max
    end_times = np.minimum(ns, maximum - seconds * 1_000_000_000) + seconds * 1_000_000_000
    ends = np.searchsorted(ns, end_times, side='right')
    # NaT records should never create findings (as in original rule code).
    invalid = ns == np.iinfo(np.int64).min
    ends[invalid] = np.flatnonzero(invalid)
    return rows, stamps, ends


def _episodes(stamps, ends, counts, threshold):
    """Merge overlapping qualifying windows in O(n) rather than O(n²)."""
    current = None
    for i in np.flatnonzero(counts >= threshold):
        stop = int(ends[i])
        if stop <= i:
            continue
        end_i = stop - 1
        if current is not None and stamps[i] <= stamps[current[4]]:
            if end_i > current[4]:
                current[4] = end_i
            if counts[i] > current[2]:
                current[2] = int(counts[i])
                current[3] = i
        else:
            if current is not None:
                yield current
            current = [i, end_i, int(counts[i]), i, end_i]
    if current is not None:
        yield current


def _count_distinct_ports(rows, ends):
    """Maintain a moving Counter of destination ports in O(n)."""
    counts = np.zeros(len(rows), dtype=np.int32)
    current = Counter()
    right = 0
    for left, end in enumerate(ends):
        while right < int(end):
            key = int(rows[right][4])
            current[key] += 1
            right += 1
        counts[left] = len(current)
        key = int(rows[left][4])
        current[key] -= 1
        if current[key] == 0:
            del current[key]
    return counts


def _fast_connection_findings(connection):
    """R01: one SQL record per flow, one pass through each source group."""
    query = '''
        SELECT flow_id, MIN(ts) AS ts, src_ip, dest_ip, dest_port
        FROM events
        WHERE flow_id IS NOT NULL AND src_ip IS NOT NULL
        GROUP BY flow_id
        ORDER BY src_ip, ts
    '''
    findings = []
    for source_ip, source_rows in _group_rows(connection.execute(query), 2):
        rows, stamps, ends = _window_bounds(
            source_rows, 1, _det.HIGH_CONNECTION_WINDOW_SECONDS
        )
        counts = ends - np.arange(len(rows))
        for episode in _episodes(stamps, ends, counts, _det.HIGH_CONNECTION_THRESHOLD):
            first, _, peak, peak_i, last = episode
            used_rows = rows[first:last + 1]
            flow_ids = sorted({r[0] for r in used_rows})
            destinations = sorted({r[3] for r in used_rows if r[3] is not None})
            start, end = stamps[first], stamps[last]
            findings.append(_det.create_finding(
                rule_id='R01', rule_name='High Connection Rate',
                timestamp=start, source_ip=source_ip,
                description=(f'Source repeatedly exceeded the threshold of '
                             f'{_det.HIGH_CONNECTION_THRESHOLD} flows within '
                             f'{_det.HIGH_CONNECTION_WINDOW_SECONDS} seconds.'),
                priority='Medium', flow_ids=flow_ids,
                details={
                    'episode_id': f'R01-{len(findings)+1:04d}',
                    'episode_start': start,
                    'episode_end': end,
                    'max_flow_count': int(peak),
                    'max_flow_timestamp': stamps[peak_i],
                    'total_flows': len(flow_ids),
                    'destination_ips': destinations,
                },
            ))
    return findings


def _fast_multi_port_findings(connection):
    """R02: filtering before flow deduplication matches the original rule."""
    query = '''
        SELECT flow_id, MIN(ts) AS ts, src_ip, dest_ip, dest_port
        FROM events
        WHERE flow_id IS NOT NULL AND src_ip IS NOT NULL
          AND dest_ip IS NOT NULL AND dest_port IS NOT NULL
          AND mits_v3_internal_ip(src_ip) = 0
          AND mits_v3_internal_ip(dest_ip) = 1
        GROUP BY flow_id
        ORDER BY src_ip, ts
    '''
    findings = []
    for source_ip, source_rows in _group_rows(connection.execute(query), 2):
        rows, stamps, ends = _window_bounds(
            source_rows, 1, _det.MULTI_PORT_WINDOW_SECONDS
        )
        counts = _count_distinct_ports(rows, ends)
        for first, _, peak, peak_i, last in _episodes(
            stamps, ends, counts, _det.MULTI_PORT_THRESHOLD
        ):
            used_rows = rows[first:last + 1]
            flow_ids = sorted({r[0] for r in used_rows})
            ports = sorted({int(r[4]) for r in used_rows})
            dests = sorted({r[3] for r in used_rows if r[3] is not None})
            start, end = stamps[first], stamps[last]
            findings.append(_det.create_finding(
                rule_id='R02', rule_name='Multi-Port Activity',
                timestamp=start, source_ip=source_ip,
                description=(f'Source contacted at least {_det.MULTI_PORT_THRESHOLD} '
                             f'distinct destination ports within '
                             f'{_det.MULTI_PORT_WINDOW_SECONDS} seconds.'),
                priority='Medium', flow_ids=flow_ids,
                details={
                    'episode_id': f'R02-{len(findings)+1:04d}',
                    'episode_start': start, 'episode_end': end,
                    'max_port_count': int(peak),
                    'max_port_timestamp': stamps[peak_i],
                    'destination_ports': ports,
                    'destination_ips': dests,
                    'total_flows': len(flow_ids),
                },
            ))
    return findings


def _fast_failed_auth_findings(connection):
    """R03: parse FTP events only and stop after the first match per source."""
    query = '''
        SELECT id, ts, flow_id, src_ip, dest_ip, dest_port, raw
        FROM events
        WHERE event_type = 'ftp' AND src_ip IS NOT NULL
        ORDER BY src_ip, ts
    '''
    findings = []
    for source_ip, all_rows in _group_rows(connection.execute(query), 3):
        rows = []
        for row in all_rows:
            if not row[6]:
                continue
            try:
                data = _json.loads(row[6])
            except (TypeError, ValueError):
                continue
            replies = (data.get('ftp') or {}).get('reply', [])
            if not isinstance(replies, list):
                replies = [replies]
            if any('Login incorrect' in str(reply) for reply in replies):
                rows.append(row)
        if not rows:
            continue
        rows, stamps, ends = _window_bounds(rows, 1, _det.FAILED_AUTH_WINDOW_SECONDS)
        counts = ends - np.arange(len(rows))
        qualifying = np.flatnonzero(counts >= _det.FAILED_AUTH_THRESHOLD)
        if len(qualifying) == 0:
            continue
        first = int(qualifying[0])
        window = rows[first:int(ends[first])]
        findings.append(_det.create_finding(
            rule_id='R03', rule_name='Repeated Failed Authentication',
            timestamp=stamps[first], source_ip=source_ip,
            description=(f'Source generated {len(window)} failed FTP '
                         f'authentication attempts within '
                         f'{_det.FAILED_AUTH_WINDOW_SECONDS} seconds.'),
            priority='Medium',
            event_ids=[r[0] for r in window],
            flow_ids=[r[2] for r in window],
            details={
                'window_start': stamps[first],
                'window_end': stamps[int(ends[first])-1],
                'failed_attempts': len(window),
                'destination_ips': list(dict.fromkeys(r[4] for r in window if r[4] is not None)),
                'destination_ports': list(dict.fromkeys(r[5] for r in window if r[5] is not None)),
            },
        ))
    return findings


def _fast_protocol_findings(connection):
    """R04: parse only relevant anomaly payloads, once per event."""
    query = '''
        SELECT id, ts, flow_id, src_ip, dest_ip, dest_port, raw
        FROM events
        WHERE event_type = 'anomaly'
          AND src_ip IS NOT NULL AND dest_ip IS NOT NULL
        ORDER BY src_ip, ts
    '''
    findings = []
    for source_ip, all_rows in _group_rows(connection.execute(query), 3):
        if _is_internal_ip(source_ip):
            continue
        rows = [r for r in all_rows if _is_internal_ip(r[4])]
        if not rows:
            continue
        rows, stamps, ends = _window_bounds(
            rows, 1, _det.PROTOCOL_ANOMALY_WINDOW_SECONDS
        )
        counts = ends - np.arange(len(rows))
        for first, _, peak, peak_i, last in _episodes(
            stamps, ends, counts, _det.PROTOCOL_ANOMALY_THRESHOLD
        ):
            window = rows[first:last + 1]
            event_ids = sorted({r[0] for r in window})
            flow_ids = sorted({r[2] for r in window if r[2] is not None})
            ports = sorted({r[5] for r in window if r[5] is not None})
            dests = sorted({r[4] for r in window if r[4] is not None})
            anomaly_types = set()
            for r in window:
                try:
                    data = _json.loads(r[6])
                    category = (data.get('anomaly') or {}).get('event')
                    if category:
                        anomaly_types.add(category)
                except (TypeError, ValueError, AttributeError):
                    continue
            start, end = stamps[first], stamps[last]
            findings.append(_det.create_finding(
                rule_id='R04', rule_name='Repeated External Protocol Anomaly',
                timestamp=start, source_ip=source_ip,
                description=(f'External source repeatedly generated protocol '
                             f'anomalies within {_det.PROTOCOL_ANOMALY_WINDOW_SECONDS} seconds.'),
                priority='Medium', event_ids=event_ids,
                flow_ids=flow_ids,
                details={
                    'episode_id': f'R04-{len(findings)+1:04d}',
                    'episode_start': start, 'episode_end': end,
                    'max_anomaly_count': int(peak),
                    'max_anomaly_timestamp': stamps[peak_i],
                    'anomaly_types': sorted(anomaly_types),
                    'destination_ips': dests,
                    'destination_ports': ports,
                    'total_events': len(event_ids),
                    'total_flows': len(flow_ids),
                },
            ))
    return findings


def create_findings():
    """Run efficient per-rule SQLite detection, without full DataFrame loads."""
    if os.getenv('MITS_V3_USE_ORIGINAL_DETECTION', '0') == '1':
        return _v2_create_findings()
    findings = []
    rules = (
        ('R01 high connection', _fast_connection_findings),
        ('R02 multi-port', _fast_multi_port_findings),
        ('R03 failed authentication', _fast_failed_auth_findings),
        ('R04 protocol anomaly', _fast_protocol_findings),
    )
    with _open_events_readonly() as connection:
        for label, function in rules:
            started = perf_counter()
            rule_findings = function(connection)
            findings.extend(rule_findings)
            print(f'  {label}: {len(rule_findings):,} findings in '
                  f'{perf_counter()-started:.2f} s', flush=True)
    for index, finding in enumerate(findings, start=1):
        if 'finding_id' not in finding:
            finding['finding_id'] = get_finding_id(finding, index)
    return findings


def main():
    """Time every stage to locate the next bottleneck on real datasets."""
    started = perf_counter()
    print('=' * 75)
    print('MITS AUTOMATIC CASE PRIORITIZATION - V3')
    print('=' * 75)
    print(f'Isolation Forest trees: {MODEL_ESTIMATORS}')
    print('Fast SQLite detection: '
          + ('disabled' if os.getenv('MITS_V3_USE_ORIGINAL_DETECTION') == '1' else 'enabled'))
    durations = {}

    def stage(label, function, *args):
        t0 = perf_counter()
        result = function(*args)
        durations[label] = perf_counter() - t0
        print(f'{label}: {durations[label]:.2f} s', flush=True)
        return result

    findings = stage('Detection', create_findings)
    print(f'Findings: {len(findings):,}')
    cases = stage('Case correlation', build_candidate_cases, findings)
    print(f'Cases: {len(cases):,}')
    sessions = stage('Session creation', create_network_sessions)
    print(f'Sessions: {len(sessions):,}')
    prioritized_cases, feature_frame, variable_columns = stage(
        'Feature extraction + model', prioritize_cases, cases, findings, sessions
    )
    print_results(prioritized_cases, variable_columns)
    paths = stage('Write output', save_results, prioritized_cases, feature_frame)
    print('Output:')
    for path in paths:
        print(f'  {path}')
    print('--- Stage timing ---')
    for label, secs in durations.items():
        print(f'  {label:<30} {secs:>9.2f} s')
    print(f'  TOTAL                         {perf_counter()-started:>9.2f} s')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
