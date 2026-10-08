"""Run the MITS honeynet analysis pipeline.

The pipeline orchestrates the existing ingestion, session-correlation,
detection, and finding-to-case correlation components. It does not contain
new detection or correlation logic.
"""

import argparse
import json
import sqlite3
from pathlib import Path

from analysis.case_correlation import build_candidate_cases, get_finding_id
from analysis.correlation import (
    build_sessions,
    create_sessions,
    group_flows,
    load_flows,
    save_sessions,
)
from analysis.detection import (
    build_high_connection_findings,
    build_multi_port_findings,
    build_protocol_anomaly_findings,
    detect_repeated_failed_authentication,
    load_events,
)
from analysis.ingest import ingest_file, open_database, print_summary
from AnomalyDetection.anomaly_detection import run_analysis as run_anomaly_analysis


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
DATABASE_FILE = REPOSITORY_ROOT / "database" / "mits.db"


FINDINGS_SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    finding_id TEXT PRIMARY KEY,
    rule_id TEXT NOT NULL,
    rule_name TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    source_ip TEXT,
    description TEXT,
    priority TEXT,
    event_ids TEXT NOT NULL,
    flow_ids TEXT NOT NULL,
    session_ids TEXT NOT NULL,
    details TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_findings_timestamp
    ON findings(timestamp);
CREATE INDEX IF NOT EXISTS idx_findings_source
    ON findings(source_ip);
CREATE INDEX IF NOT EXISTS idx_findings_rule
    ON findings(rule_id);
"""


CASES_SCHEMA = """
CREATE TABLE IF NOT EXISTS cases (
    case_id TEXT PRIMARY KEY,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    source_ips TEXT NOT NULL,
    destination_ips TEXT NOT NULL,
    finding_ids TEXT NOT NULL,
    rule_ids TEXT NOT NULL,
    finding_count INTEGER NOT NULL,
    correlation_strength TEXT NOT NULL,
    correlation_reasons TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS case_findings (
    case_id TEXT NOT NULL,
    finding_id TEXT NOT NULL,
    PRIMARY KEY (case_id, finding_id),
    FOREIGN KEY (case_id) REFERENCES cases(case_id),
    FOREIGN KEY (finding_id) REFERENCES findings(finding_id)
);

CREATE INDEX IF NOT EXISTS idx_cases_first_seen
    ON cases(first_seen);
CREATE INDEX IF NOT EXISTS idx_cases_source
    ON cases(source_ips);
CREATE INDEX IF NOT EXISTS idx_case_findings_finding
    ON case_findings(finding_id);
"""


def normalize_findings(findings):
    """Assign stable finding IDs using the existing case-correlation scheme."""
    normalized = []

    for index, finding in enumerate(findings, start=1):
        record = finding.copy()
        record["finding_id"] = get_finding_id(finding, index)
        normalized.append(record)

    return normalized


def create_result_tables(connection):
    """Create fresh derived-result tables for the current analysis run.

    Findings and cases are derived from the current dataset, so they can be
    safely rebuilt when the pipeline is run again. Older case-correlation
    tables are removed first so their foreign-key relationships do not
    interfere with the current schema.
    """
    connection.execute("DROP TABLE IF EXISTS case_findings")
    connection.execute("DROP TABLE IF EXISTS case_flows")
    connection.execute("DROP TABLE IF EXISTS cases")
    connection.execute("DROP TABLE IF EXISTS findings")

    connection.executescript(FINDINGS_SCHEMA)
    connection.executescript(CASES_SCHEMA)
    connection.commit()


def save_findings(connection, findings):
    """Replace persisted findings with the results of the current run."""
    rows = []
    for finding in findings:
        rows.append(
            (
                finding["finding_id"],
                finding["rule_id"],
                finding["rule_name"],
                str(finding["timestamp"]),
                finding.get("source_ip"),
                finding.get("description"),
                finding.get("priority"),
                json.dumps(finding.get("event_ids", []), default=str),
                json.dumps(finding.get("flow_ids", []), default=str),
                json.dumps(finding.get("session_ids", []), default=str),
                json.dumps(finding.get("details", {}), default=str),
            )
        )

    connection.executemany(
        """
        INSERT INTO findings (
            finding_id, rule_id, rule_name, timestamp, source_ip,
            description, priority, event_ids, flow_ids, session_ids, details
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        rows,
    )
    connection.commit()


def save_cases(connection, cases):
    """Persist candidate cases and their finding relationships."""

    case_rows = []
    link_rows = []

    # Get the finding IDs that actually exist in the database.
    existing_finding_ids = {
        row[0]
        for row in connection.execute(
            "SELECT finding_id FROM findings"
        ).fetchall()
    }

    for case in cases:
        case_rows.append(
            (
                case["case_id"],
                str(case["first_seen"]),
                str(case["last_seen"]),
                json.dumps(
                    case.get("source_ips", []),
                    default=str,
                ),
                json.dumps(
                    case.get("destination_ips", []),
                    default=str,
                ),
                json.dumps(
                    case.get("finding_ids", []),
                    default=str,
                ),
                json.dumps(
                    case.get("rule_ids", []),
                    default=str,
                ),
                case["finding_count"],
                case["correlation_strength"],
                json.dumps(
                    case.get("correlation_reasons", []),
                    default=str,
                ),
            )
        )

        for finding_id in case.get("finding_ids", []):
            if finding_id not in existing_finding_ids:
                raise ValueError(
                    "Case references finding "
                    f"{finding_id}, but that finding does not "
                    "exist in the findings table."
                )

            link_rows.append(
                (
                    case["case_id"],
                    finding_id,
                )
            )

    connection.executemany(
        """
        INSERT INTO cases (
            case_id,
            first_seen,
            last_seen,
            source_ips,
            destination_ips,
            finding_ids,
            rule_ids,
            finding_count,
            correlation_strength,
            correlation_reasons
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        case_rows,
    )

    connection.executemany(
        """
        INSERT INTO case_findings (
            case_id,
            finding_id
        )
        VALUES (?, ?)
        """,
        link_rows,
    )

    connection.commit()


def run_session_correlation(connection):
    """Run the existing flow-to-session correlation and persist sessions."""
    flows = load_flows(connection)
    groups = group_flows(flows)
    raw_sessions = create_sessions(groups)
    sessions = build_sessions(raw_sessions)
    save_sessions(connection, sessions)
    return sessions


def run_detection(database_path):
    """Run all currently implemented rule-based detection rules."""
    events = load_events(database_path)

    r01 = build_high_connection_findings(events)
    r02 = build_multi_port_findings(events)
    r03 = detect_repeated_failed_authentication(events)
    r04 = build_protocol_anomaly_findings(events)

    findings = r01 + r02 + r03 + r04
    findings.sort(key=lambda finding: finding["timestamp"])

    return events, findings


def run_pipeline(
    database_path=DATABASE_FILE,
    input_files=None,
    with_anomaly=False,
    anomaly_window_seconds=60,
    anomaly_threshold=3.5,
    anomaly_min_source_windows=5,
):
    """Run ingestion (when requested), correlation, detection and case creation.

    Returns a dictionary containing the in-memory results from the run.

    Statistical anomaly detection is optional because it is a separate detector
    from the existing rule-based detection pipeline. When enabled, it reads the
    same shared SQLite events table and stores its own derived anomaly tables.
    """
    database_path = Path(database_path)
    database_path.parent.mkdir(parents=True, exist_ok=True)

    if input_files:
        connection = open_database(database_path)
        try:
            for input_file in input_files:
                path = Path(input_file)
                if not path.is_file():
                    raise FileNotFoundError(
                        f"Input file not found: {path}"
                    )

                import time

                start_time = time.perf_counter()
                results = ingest_file(connection, path)
                print_summary(
                    path,
                    *results,
                    time.perf_counter() - start_time,
                )

            connection.executescript(
                """
                CREATE INDEX IF NOT EXISTS idx_events_flow_id
                    ON events(flow_id);
                CREATE INDEX IF NOT EXISTS idx_events_community_id
                    ON events(community_id);
                CREATE INDEX IF NOT EXISTS idx_events_src_ip
                    ON events(src_ip);
                CREATE INDEX IF NOT EXISTS idx_events_ts
                    ON events(ts);
                CREATE INDEX IF NOT EXISTS idx_events_event_type
                    ON events(event_type);
                """
            )
            connection.commit()
        finally:
            connection.close()

    if not database_path.exists():
        raise FileNotFoundError(
            f"Database not found: {database_path}. "
            "Run ingestion first or provide an existing database."
        )

    with sqlite3.connect(database_path) as connection:
        sessions = run_session_correlation(connection)
        events, findings = run_detection(database_path)

        findings = normalize_findings(findings)
        
        create_result_tables(connection)
        
        save_findings(
            connection,
            findings,
        )
        
        cases = build_candidate_cases(findings)
        
        save_cases(
            connection,
            cases,
        )

        connection.commit()

    anomaly_result = None
    if with_anomaly:
        anomaly_result = run_anomaly_analysis(
            database_path,
            window_seconds=anomaly_window_seconds,
            threshold=anomaly_threshold,
            min_source_windows=anomaly_min_source_windows,
        )

    return {
        "event_count": len(events),
        "session_count": len(sessions),
        "finding_count": len(findings),
        "case_count": len(cases),
        "findings": findings,
        "cases": cases,
        "anomaly_result": anomaly_result,
    }


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Run the MITS honeynet analysis pipeline."
    )
    parser.add_argument(
        "inputs",
        nargs="*",
        type=Path,
        help="optional EVE-JSON files to ingest before analysis",
    )
    parser.add_argument(
        "--db",
        type=Path,
        default=DATABASE_FILE,
        help="path to the project SQLite database",
    )
    parser.add_argument(
        "--with-anomaly",
        action="store_true",
        help="run statistical anomaly detection after case generation",
    )
    parser.add_argument(
        "--anomaly-window-seconds",
        type=int,
        default=60,
        help="time-window size used by anomaly detection (default: 60)",
    )
    parser.add_argument(
        "--anomaly-threshold",
        type=float,
        default=3.5,
        help="modified z-score threshold used by anomaly detection (default: 3.5)",
    )
    parser.add_argument(
        "--anomaly-min-source-windows",
        type=int,
        default=5,
        help="minimum source windows required for a source baseline (default: 5)",
    )
    return parser.parse_args()


def main():
    arguments = parse_arguments()

    print("======================================")
    print("MITS HONEYNET ANALYSIS PIPELINE")
    print("======================================")
    print(f"Database: {arguments.db}")

    try:
        results = run_pipeline(
            database_path=arguments.db,
            input_files=arguments.inputs or None,
            with_anomaly=arguments.with_anomaly,
            anomaly_window_seconds=arguments.anomaly_window_seconds,
            anomaly_threshold=arguments.anomaly_threshold,
            anomaly_min_source_windows=arguments.anomaly_min_source_windows,
        )
    except (OSError, sqlite3.Error, ValueError) as error:
        print(f"Pipeline failed: {error}")
        return 1

    print("\n======================================")
    print("PIPELINE SUMMARY")
    print("======================================")
    print(f"Events:    {results['event_count']:,}")
    print(f"Sessions:  {results['session_count']:,}")
    print(f"Findings:  {results['finding_count']:,}")
    print(f"Cases:     {results['case_count']:,}")

    anomaly_result = results.get("anomaly_result")
    if anomaly_result is not None:
        print(f"Anomaly windows:  {anomaly_result.windows_created:,}")
        print(f"Anomaly baselines:{anomaly_result.baselines_created:,}")
        print(f"Anomaly findings: {anomaly_result.findings_created:,}")
        print(f"Anomaly links:    {anomaly_result.event_links_created:,}")

    print("Analysis results saved to SQLite.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())