import json
import sqlite3
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

DATABASE_FILE = Path(__file__).resolve().parent.parent / "database" / "mits_test.db"
INACTIVITY_GAP_MINUTES = 5
LARGEST_SESSION_LIMIT = 10


def parse_timestamp(timestamp):
    if timestamp is None:
        return None
    timestamp = str(timestamp)
    if timestamp.endswith("Z"):
        timestamp = timestamp[:-1] + "+00:00"
    if (
        len(timestamp) >= 5
        and timestamp[-5] in ("+", "-")
        and timestamp[-3] != ":"
    ):
        timestamp = timestamp[:-2] + ":" + timestamp[-2:]
    return datetime.fromisoformat(timestamp)


def load_flows(connection):
    """Aggregate SQLite events into one record per flow_id."""
    print("Step 1: Aggregating events into flows...")
    rows = connection.execute(
        """
        SELECT
            flow_id,
            MIN(ts) AS first_event_ts,
            MAX(ts) AS last_event_ts,
            MAX(flow_start) AS flow_start,
            MAX(flow_end) AS flow_end,
            MAX(src_ip) AS src_ip,
            MAX(src_port) AS src_port,
            MAX(dest_ip) AS dest_ip,
            MAX(dest_port) AS dest_port,
            MAX(proto) AS proto,
            COUNT(*) AS event_count
        FROM events
        WHERE flow_id IS NOT NULL
        GROUP BY flow_id
        ORDER BY flow_id
        """
    ).fetchall()

    columns = [
        "flow_id", "first_event_ts", "last_event_ts", "flow_start",
        "flow_end", "src_ip", "src_port", "dest_ip", "dest_port",
        "proto", "event_count",
    ]

    flows = []
    fallback_count = 0
    invalid_count = 0

    for row in rows:
        flow = dict(zip(columns, row))
        start = flow["flow_start"]
        end = flow["flow_end"]

        if start is None:
            start = flow["first_event_ts"]
            fallback_count += 1
        if end is None:
            end = flow["last_event_ts"]
            fallback_count += 1

        if start is None or end is None:
            invalid_count += 1
            continue

        flow["flow_start"] = parse_timestamp(start)
        flow["flow_end"] = parse_timestamp(end)
        flows.append(flow)

    print(f"Unique flows:             {len(rows):,}")
    print(f"Usable flows:             {len(flows):,}")
    print(f"Timestamp fallbacks used: {fallback_count:,}")
    print(f"Invalid flows skipped:    {invalid_count:,}")
    return flows


def group_flows(flows):
    """Group flows by source IP, destination IP and protocol."""
    print("\nStep 2: Grouping flows by network relationship...")
    groups = defaultdict(list)
    for flow in flows:
        key = (flow["src_ip"], flow["dest_ip"], flow["proto"])
        groups[key].append(flow)
    print(f"Network groups:           {len(groups):,}")
    return groups


def create_sessions(flow_groups):
    """Sessionize flows using a 5-minute inactivity threshold.

    The current session keeps its latest flow_end. Overlapping flows are
    therefore naturally included, and destination port is not a boundary.
    """
    print(
        "\nStep 3: Creating sessions using "
        f"{INACTIVITY_GAP_MINUTES}-minute inactivity threshold..."
    )
    gap = timedelta(minutes=INACTIVITY_GAP_MINUTES)
    sessions = []

    for related_flows in flow_groups.values():
        related_flows.sort(key=lambda flow: flow["flow_start"])
        current = []
        latest_end = None

        for flow in related_flows:
            if not current:
                current = [flow]
                latest_end = flow["flow_end"]
                continue

            if flow["flow_start"] <= latest_end + gap:
                current.append(flow)
                latest_end = max(latest_end, flow["flow_end"])
            else:
                sessions.append(current)
                current = [flow]
                latest_end = flow["flow_end"]

        if current:
            sessions.append(current)

    return sessions


def build_sessions(raw_sessions):
    print("\nStep 4: Building session objects...")
    raw_sessions.sort(key=lambda s: min(f["flow_start"] for f in s))
    sessions = []

    for number, flows in enumerate(raw_sessions, start=1):
        first_seen = min(f["flow_start"] for f in flows)
        last_seen = max(f["flow_end"] for f in flows)
        destination_ports = sorted({
            f["dest_port"] for f in flows if f["dest_port"] is not None
        })
        source_ports = sorted({
            f["src_port"] for f in flows if f["src_port"] is not None
        })

        sessions.append({
            "session_id": f"SESSION-{number:05d}",
            "src_ip": flows[0]["src_ip"],
            "dest_ip": flows[0]["dest_ip"],
            "protocol": flows[0]["proto"],
            "first_seen": first_seen.isoformat(),
            "last_seen": last_seen.isoformat(),
            "duration_seconds": max(0, int((last_seen - first_seen).total_seconds())),
            "flow_count": len(flows),
            "event_count": sum(f["event_count"] for f in flows),
            "destination_ports": destination_ports,
            "source_ports": source_ports,
            "flow_ids": [f["flow_id"] for f in flows],
        })

    print(f"Sessions created:         {len(sessions):,}")
    return sessions


def validate_sessions(connection, sessions):
    print("\nStep 5: Validating flow-to-session assignment...")
    assigned = [fid for s in sessions for fid in s["flow_ids"]]
    unique_assigned = set(assigned)
    database_count = connection.execute(
        "SELECT COUNT(DISTINCT flow_id) FROM events WHERE flow_id IS NOT NULL"
    ).fetchone()[0]
    duplicates = len(assigned) - len(unique_assigned)
    missing = database_count - len(unique_assigned)

    print(f"Distinct flows in database: {database_count:,}")
    print(f"Distinct flows assigned:    {len(unique_assigned):,}")
    print(f"Duplicate assignments:      {duplicates:,}")
    print(f"Unassigned flows:            {missing:,}")
    print("Validation result:           PASS" if not duplicates and not missing else "Validation result:           REVIEW")


def print_statistics(sessions):
    print("\n======================================")
    print("SESSION STATISTICS")
    print("======================================")
    if not sessions:
        print("No sessions were created.")
        return

    durations = [s["duration_seconds"] for s in sessions]
    multi_port = sum(len(s["destination_ports"]) > 1 for s in sessions)
    print(f"Sessions:                  {len(sessions):,}")
    print(f"Flows assigned:            {sum(s['flow_count'] for s in sessions):,}")
    print(f"Events represented:        {sum(s['event_count'] for s in sessions):,}")
    print(f"Multi-port sessions:       {multi_port:,}")
    print(f"Longest session:            {max(durations) / 60:.2f} minutes")
    print(f"Average session duration:  {sum(durations) / len(durations) / 60:.2f} minutes")

    print("\nLargest sessions:")
    for session in sorted(sessions, key=lambda s: s["flow_count"], reverse=True)[:LARGEST_SESSION_LIMIT]:
        print("\n--------------------------------------")
        print(f"Session ID:       {session['session_id']}")
        print(f"Source:            {session['src_ip']}")
        print(f"Destination:       {session['dest_ip']}")
        print(f"Protocol:          {session['protocol']}")
        print(f"Destination ports: {session['destination_ports']}")
        print(f"First seen:        {session['first_seen']}")
        print(f"Last seen:         {session['last_seen']}")
        print(f"Duration:          {session['duration_seconds'] / 60:.2f} minutes")
        print(f"Flows:             {session['flow_count']}")
        print(f"Events:            {session['event_count']}")


def create_tables(connection):
    connection.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            session_id TEXT PRIMARY KEY,
            src_ip TEXT,
            dest_ip TEXT,
            protocol TEXT,
            first_seen TEXT,
            last_seen TEXT,
            duration_seconds INTEGER,
            flow_count INTEGER,
            event_count INTEGER,
            destination_ports TEXT,
            source_ports TEXT
        )
    """)
    connection.execute("""
        CREATE TABLE IF NOT EXISTS session_flows (
            session_id TEXT NOT NULL,
            flow_id INTEGER NOT NULL,
            PRIMARY KEY (session_id, flow_id),
            FOREIGN KEY (session_id) REFERENCES sessions(session_id)
        )
    """)
    connection.execute("CREATE INDEX IF NOT EXISTS idx_sessions_source ON sessions(src_ip)")
    connection.execute("CREATE INDEX IF NOT EXISTS idx_sessions_destination ON sessions(dest_ip)")
    connection.execute("CREATE INDEX IF NOT EXISTS idx_sessions_first_seen ON sessions(first_seen)")
    connection.execute("CREATE INDEX IF NOT EXISTS idx_session_flows_flow_id ON session_flows(flow_id)")


def save_sessions(connection, sessions):
    print("\nStep 6: Saving sessions to SQLite...")
    connection.execute("PRAGMA foreign_keys = ON")
    create_tables(connection)
    connection.execute("DELETE FROM session_flows")
    connection.execute("DELETE FROM sessions")

    connection.executemany("""
        INSERT INTO sessions (
            session_id, src_ip, dest_ip, protocol, first_seen, last_seen,
            duration_seconds, flow_count, event_count, destination_ports,
            source_ports
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, [
        (
            s["session_id"], s["src_ip"], s["dest_ip"], s["protocol"],
            s["first_seen"], s["last_seen"], s["duration_seconds"],
            s["flow_count"], s["event_count"],
            json.dumps(s["destination_ports"]),
            json.dumps(s["source_ports"]),
        )
        for s in sessions
    ])

    connection.executemany("""
        INSERT INTO session_flows (session_id, flow_id)
        VALUES (?, ?)
    """, [
        (s["session_id"], fid)
        for s in sessions
        for fid in s["flow_ids"]
    ])
    connection.commit()

    session_count = connection.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
    link_count = connection.execute("SELECT COUNT(*) FROM session_flows").fetchone()[0]
    print("Database updated successfully.")
    print(f"Sessions stored:           {session_count:,}")
    print(f"Session-flow links:        {link_count:,}")


def main():
    print("======================================")
    print("MITS SESSION CORRELATION")
    print("======================================")
    print(f"Database:                   {DATABASE_FILE}")
    print(f"Inactivity threshold:       {INACTIVITY_GAP_MINUTES} minutes")
    print("Maximum session duration:   None\n")

    if not DATABASE_FILE.exists():
        print(f"Database file not found: {DATABASE_FILE}")
        return 1

    try:
        with sqlite3.connect(DATABASE_FILE) as connection:
            flows = load_flows(connection)
            groups = group_flows(flows)
            raw_sessions = create_sessions(groups)
            sessions = build_sessions(raw_sessions)
            print_statistics(sessions)
            validate_sessions(connection, sessions)
            save_sessions(connection, sessions)
    except (sqlite3.Error, OSError, ValueError) as error:
        print(f"Error: {error}")
        return 1

    print("\nDone.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())