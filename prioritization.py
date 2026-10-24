import json
import math
import sqlite3
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

    findings = (
        build_high_connection_findings(events)
        + build_multi_port_findings(events)
        + detect_repeated_failed_authentication(events)
        + build_protocol_anomaly_findings(events)
    )

    for index, finding in enumerate(findings, start=1):
        if "finding_id" not in finding:
            finding["finding_id"] = get_finding_id(
                finding,
                index,
            )

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


def get_matching_sessions(case, sessions):
    case_start = to_utc_timestamp(case["first_seen"])
    case_end = to_utc_timestamp(case["last_seen"])

    source_ips = set(case.get("source_ips", []))
    destination_ips = set(case.get("destination_ips", []))

    matching_sessions = []

    for session in sessions:
        if session.get("src_ip") not in source_ips:
            continue

        if (
            destination_ips
            and session.get("dest_ip") not in destination_ips
        ):
            continue

        session_start = to_utc_timestamp(
            session["first_seen"]
        )
        session_end = to_utc_timestamp(
            session["last_seen"]
        )

        overlaps = (
            session_start <= case_end
            and session_end >= case_start
        )

        if overlaps:
            matching_sessions.append(session)

    return matching_sessions


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
            np.mean(values)
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

    matching_sessions = get_matching_sessions(
        case,
        sessions,
    )

    session_flow_ids = set()
    session_destination_ports = set()
    session_source_ports = set()
    session_protocols = []
    session_durations = []

    total_session_flows = 0
    total_session_events = 0

    for session in matching_sessions:
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
            len(matching_sessions)
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

    rows = []

    for case in cases:
        rows.append(
            build_case_features(
                case,
                finding_lookup,
                sessions,
            )
        )

    feature_frame = pd.DataFrame(
        rows,
        index=[
            case["case_id"]
            for case in cases
        ],
    )

    feature_frame = (
        feature_frame
        .replace(
            [np.inf, -np.inf],
            np.nan,
        )
        .fillna(0.0)
        .astype(float)
    )

    variable_columns = [
        column
        for column in feature_frame.columns
        if feature_frame[column].nunique(
            dropna=False
        ) > 1
    ]

    return (
        feature_frame,
        variable_columns,
    )


def calculate_priority(
    cases,
    feature_frame,
    variable_columns,
):
    prioritized_cases = [
        case.copy()
        for case in cases
    ]

    if not prioritized_cases:
        return []

    if not variable_columns:
        for index, case in enumerate(
            prioritized_cases,
            start=1,
        ):
            case["priority_rank"] = index
            case["priority_score"] = 50.0
            case["isolation_forest_score"] = 0.0
            case["isolation_forest_classification"] = (
                "Undetermined"
            )
            case["priority_features"] = (
                feature_frame.loc[
                    case["case_id"]
                ].to_dict()
            )

        return prioritized_cases

    model = IsolationForest(
        n_estimators=MODEL_ESTIMATORS,
        contamination="auto",
        random_state=MODEL_RANDOM_STATE,
        n_jobs=-1,
    )

    model_data = feature_frame[
        variable_columns
    ]

    model.fit(model_data)

    raw_scores = -model.score_samples(
        model_data
    )

    predictions = model.predict(
        model_data
    )

    score_series = pd.Series(
        raw_scores,
        index=feature_frame.index,
    )

    percentile_scores = (
        score_series.rank(
            method="average",
            pct=True,
        )
        * 100
    )

    result_lookup = {}

    for case_id in feature_frame.index:
        result_lookup[case_id] = {
            "priority_score": round(
                float(
                    percentile_scores.loc[
                        case_id
                    ]
                ),
                2,
            ),
            "isolation_forest_score": round(
                float(
                    score_series.loc[
                        case_id
                    ]
                ),
                6,
            ),
        }

    for case, prediction in zip(
        prioritized_cases,
        predictions,
    ):
        case_id = case["case_id"]

        case.update(
            result_lookup[case_id]
        )

        case[
            "isolation_forest_classification"
        ] = (
            "Anomaly"
            if prediction == -1
            else "Normal"
        )

        case["priority_features"] = (
            feature_frame.loc[
                case_id
            ].to_dict()
        )

    prioritized_cases.sort(
        key=lambda case: (
            -case["priority_score"],
            -case["isolation_forest_score"],
            to_utc_timestamp(
                case["first_seen"]
            ),
        )
    )

    for rank, case in enumerate(
        prioritized_cases,
        start=1,
    ):
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
        / "prioritized_cases.json"
    )
    csv_path = (
        OUTPUT_DIRECTORY
        / "prioritized_cases.csv"
    )
    feature_path = (
        OUTPUT_DIRECTORY
        / "prioritization_features.csv"
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

    summary_rows = []

    for case in prioritized_cases:
        summary_rows.append({
            "priority_rank": case[
                "priority_rank"
            ],
            "case_id": case["case_id"],
            "priority_score": case[
                "priority_score"
            ],
            "isolation_forest_score": case[
                "isolation_forest_score"
            ],
            "classification": case[
                "isolation_forest_classification"
            ],
            "first_seen": case[
                "first_seen"
            ],
            "last_seen": case[
                "last_seen"
            ],
            "finding_count": case[
                "finding_count"
            ],
            "rule_ids": ",".join(
                case.get(
                    "rule_ids",
                    [],
                )
            ),
            "source_ips": ",".join(
                case.get(
                    "source_ips",
                    [],
                )
            ),
            "destination_ips": ",".join(
                case.get(
                    "destination_ips",
                    [],
                )
            ),
        })

    pd.DataFrame(
        summary_rows
    ).to_csv(
        csv_path,
        index=False,
    )

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

    for case in prioritized_cases:
        print(
            f"{case['priority_rank']:>4} | "
            f"{case['case_id']:<9} | "
            f"{case['priority_score']:>8.2f} | "
            f"{case['isolation_forest_score']:>8.6f} | "
            f"{case['isolation_forest_classification']:<14} | "
            f"{case['finding_count']}"
        )


def main():
    print("=" * 100)
    print("MITS AUTOMATIC CASE PRIORITIZATION")
    print("=" * 100)
    print(
        "Method: Isolation Forest "
        "without manually assigned rule severity"
    )

    findings = create_findings()

    print(
        f"Findings loaded: "
        f"{len(findings)}"
    )

    cases = build_candidate_cases(
        findings
    )

    print(
        f"Candidate cases: "
        f"{len(cases)}"
    )

    sessions = create_network_sessions()

    print(
        f"Network sessions available: "
        f"{len(sessions)}"
    )

    (
        prioritized_cases,
        feature_frame,
        variable_columns,
    ) = prioritize_cases(
        cases,
        findings,
        sessions,
    )

    print_results(
        prioritized_cases,
        variable_columns,
    )

    (
        json_path,
        csv_path,
        feature_path,
    ) = save_results(
        prioritized_cases,
        feature_frame,
    )

    print()
    print("Output files:")
    print(f"  {json_path}")
    print(f"  {csv_path}")
    print(f"  {feature_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
