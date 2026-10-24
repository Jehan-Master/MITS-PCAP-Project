import json
import sqlite3
from collections import Counter, defaultdict
from datetime import datetime, timedelta

EVE_FILE = "eve_2026-06-20.jsonl"
DATABASE_FILE = "mits.db"
INACTIVITY_GAP_MINUTES = 5
MAX_CASE_DURATION_MINUTES = 30
LARGEST_CASE_LIMIT = 10


def parse_timestamp(timestamp):
    if timestamp.endswith("Z"):
        timestamp = timestamp[:-1] + "+00:00"

    if (
        len(timestamp) >= 5
        and timestamp[-5] in ("+", "-")
        and timestamp[-3] != ":"
    ):
        timestamp = timestamp[:-2] + ":" + timestamp[-2:]

    return datetime.fromisoformat(timestamp)


def load_flows():
    flows = {}
    total_events = 0
    events_without_flow_id = 0
    events_without_timestamp = 0
    invalid_timestamps = 0
    json_errors = 0

    print("Step 1: Grouping events by flow_id...")

    with open(EVE_FILE, "r", encoding="utf-8", errors="ignore") as eve_file:
        for line in eve_file:
            total_events += 1

            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                json_errors += 1
                continue

            flow_id = event.get("flow_id")
            if flow_id is None:
                events_without_flow_id += 1
                continue

            timestamp = event.get("timestamp")
            if timestamp is None:
                events_without_timestamp += 1
                continue

            try:
                timestamp_value = parse_timestamp(timestamp)
            except ValueError:
                invalid_timestamps += 1
                continue

            if flow_id not in flows:
                flows[flow_id] = {
                    "flow_id": flow_id,
                    "src_ip": event.get("src_ip"),
                    "src_port": event.get("src_port"),
                    "dest_ip": event.get("dest_ip"),
                    "dest_port": event.get("dest_port"),
                    "proto": event.get("proto"),
                    "first_seen": timestamp_value,
                    "last_seen": timestamp_value,
                    "event_count": 0,
                    "event_types": Counter(),
                }

            flow = flows[flow_id]

            if flow["src_ip"] is None:
                flow["src_ip"] = event.get("src_ip")
            if flow["src_port"] is None:
                flow["src_port"] = event.get("src_port")
            if flow["dest_ip"] is None:
                flow["dest_ip"] = event.get("dest_ip")
            if flow["dest_port"] is None:
                flow["dest_port"] = event.get("dest_port")
            if flow["proto"] is None:
                flow["proto"] = event.get("proto")

            flow["event_count"] += 1
            event_type = event.get("event_type", "unknown")
            flow["event_types"][event_type] += 1

            if timestamp_value < flow["first_seen"]:
                flow["first_seen"] = timestamp_value
            if timestamp_value > flow["last_seen"]:
                flow["last_seen"] = timestamp_value

    print(f"Total events:             {total_events:,}")
    print(f"Events without flow_id:   {events_without_flow_id:,}")
    print(f"Events without timestamp: {events_without_timestamp:,}")
    print(f"Invalid timestamps:       {invalid_timestamps:,}")
    print(f"JSON errors:              {json_errors:,}")
    print(f"Unique flows:             {len(flows):,}")

    return flows


def group_related_flows(flows):
    print()
    print("Step 2: Grouping related flows...")

    flow_groups = defaultdict(list)

    for flow in flows.values():
        group_key = (
            flow["src_ip"],
            flow["dest_ip"],
            flow["dest_port"],
            flow["proto"],
        )
        flow_groups[group_key].append(flow)

    print(f"Related flow groups:      {len(flow_groups):,}")
    return flow_groups


def create_time_based_cases(flow_groups):
    print()
    print(
        "Step 3: Creating cases using "
        f"{INACTIVITY_GAP_MINUTES}-minute inactivity gap and "
        f"{MAX_CASE_DURATION_MINUTES}-minute maximum duration..."
    )

    inactivity_gap = timedelta(minutes=INACTIVITY_GAP_MINUTES)
    maximum_case_duration = timedelta(minutes=MAX_CASE_DURATION_MINUTES)
    raw_cases = []

    for related_flows in flow_groups.values():
        related_flows.sort(key=lambda flow: flow["first_seen"])
        current_case_flows = []
        case_start_time = None
        previous_activity_time = None

        for flow in related_flows:
            flow_start = flow["first_seen"]
            flow_end = flow["last_seen"]

            if not current_case_flows:
                current_case_flows.append(flow)
                case_start_time = flow_start
                previous_activity_time = flow_end
                continue

            inactivity = flow_start - previous_activity_time
            if inactivity < timedelta(0):
                inactivity = timedelta(0)

            case_duration = flow_start - case_start_time

            if (
                inactivity <= inactivity_gap
                and case_duration <= maximum_case_duration
            ):
                current_case_flows.append(flow)
                if flow_end > previous_activity_time:
                    previous_activity_time = flow_end
            else:
                raw_cases.append(current_case_flows.copy())
                current_case_flows = [flow]
                case_start_time = flow_start
                previous_activity_time = flow_end

        if current_case_flows:
            raw_cases.append(current_case_flows.copy())

    return raw_cases


def build_final_cases(raw_cases):
    print()
    print("Step 4: Building final case objects...")

    raw_cases.sort(
        key=lambda case_flows: min(
            flow["first_seen"] for flow in case_flows
        )
    )

    final_cases = []

    for case_number, related_flows in enumerate(raw_cases, start=1):
        first_flow = related_flows[0]
        first_seen = min(flow["first_seen"] for flow in related_flows)
        last_seen = max(flow["last_seen"] for flow in related_flows)
        case_duration = last_seen - first_seen
        total_events = 0
        combined_event_types = Counter()
        flow_ids = []

        for flow in related_flows:
            total_events += flow["event_count"]
            combined_event_types.update(flow["event_types"])
            flow_ids.append(flow["flow_id"])

        final_cases.append(
            {
                "case_id": f"CASE-{case_number:05d}",
                "src_ip": first_flow["src_ip"],
                "dest_ip": first_flow["dest_ip"],
                "dest_port": first_flow["dest_port"],
                "protocol": first_flow["proto"],
                "first_seen": first_seen.isoformat(),
                "last_seen": last_seen.isoformat(),
                "duration_seconds": max(
                    0, int(case_duration.total_seconds())
                ),
                "flow_count": len(related_flows),
                "event_count": total_events,
                "event_types": dict(combined_event_types),
                "flow_ids": flow_ids,
            }
        )

    print(f"Cases created:            {len(final_cases):,}")
    return final_cases


def show_largest_cases(final_cases):
    largest_cases = sorted(
        final_cases,
        key=lambda case: case["flow_count"],
        reverse=True,
    )

    print()
    print("======================================")
    print("LARGEST CASES")
    print("======================================")

    for case in largest_cases[:LARGEST_CASE_LIMIT]:
        duration_minutes = case["duration_seconds"] / 60

        print()
        print("--------------------------------------")
        print(f"Case ID:       {case['case_id']}")
        print(f"Source:        {case['src_ip']}")
        print(
            f"Destination:   {case['dest_ip']}:{case['dest_port']}"
        )
        print(f"Protocol:      {case['protocol']}")
        print(f"First seen:    {case['first_seen']}")
        print(f"Last seen:     {case['last_seen']}")
        print(f"Duration:      {duration_minutes:.2f} minutes")
        print(f"Flows:         {case['flow_count']}")
        print(f"Events:        {case['event_count']}")
        print(f"Event types:   {case['event_types']}")


def create_database_tables(connection):
    cursor = connection.cursor()

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS cases (
            case_id TEXT PRIMARY KEY,
            src_ip TEXT,
            dest_ip TEXT,
            dest_port INTEGER,
            protocol TEXT,
            first_seen TEXT,
            last_seen TEXT,
            duration_seconds INTEGER,
            flow_count INTEGER,
            event_count INTEGER,
            event_types TEXT
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS case_flows (
            case_id TEXT NOT NULL,
            flow_id INTEGER NOT NULL,
            PRIMARY KEY (case_id, flow_id),
            FOREIGN KEY (case_id) REFERENCES cases(case_id)
        )
        """
    )

    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_cases_source
        ON cases(src_ip)
        """
    )
    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_cases_destination
        ON cases(dest_ip, dest_port)
        """
    )
    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_case_flows_flow_id
        ON case_flows(flow_id)
        """
    )

    connection.commit()


def save_cases_to_database(final_cases):
    print()
    print("Step 5: Saving cases to SQLite...")

    with sqlite3.connect(DATABASE_FILE) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        create_database_tables(connection)
        cursor = connection.cursor()

        cursor.execute("DELETE FROM case_flows")
        cursor.execute("DELETE FROM cases")

        case_rows = [
            (
                case["case_id"],
                case["src_ip"],
                case["dest_ip"],
                case["dest_port"],
                case["protocol"],
                case["first_seen"],
                case["last_seen"],
                case["duration_seconds"],
                case["flow_count"],
                case["event_count"],
                json.dumps(case["event_types"], sort_keys=True),
            )
            for case in final_cases
        ]

        cursor.executemany(
            """
            INSERT INTO cases (
                case_id,
                src_ip,
                dest_ip,
                dest_port,
                protocol,
                first_seen,
                last_seen,
                duration_seconds,
                flow_count,
                event_count,
                event_types
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            case_rows,
        )

        case_flow_rows = [
            (case["case_id"], flow_id)
            for case in final_cases
            for flow_id in case["flow_ids"]
        ]

        cursor.executemany(
            """
            INSERT INTO case_flows (case_id, flow_id)
            VALUES (?, ?)
            """,
            case_flow_rows,
        )

        cursor.execute("SELECT COUNT(*) FROM cases")
        case_count = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM case_flows")
        case_flow_count = cursor.fetchone()[0]

    print()
    print("Database updated successfully.")
    print(f"Cases stored:            {case_count:,}")
    print(f"Case-flow links:         {case_flow_count:,}")
    print(f"Database file:           {DATABASE_FILE}")

    return case_count, case_flow_count


def main():
    print("======================================")
    print("MITS AGGREGATION & CORRELATION")
    print("======================================")
    print(f"Input file:              {EVE_FILE}")
    print(f"Database:                {DATABASE_FILE}")
    print(f"Inactivity gap:          {INACTIVITY_GAP_MINUTES} minutes")
    print(
        "Maximum case duration:   "
        f"{MAX_CASE_DURATION_MINUTES} minutes"
    )
    print()

    try:
        flows = load_flows()
        flow_groups = group_related_flows(flows)
        raw_cases = create_time_based_cases(flow_groups)
        final_cases = build_final_cases(raw_cases)
        show_largest_cases(final_cases)
        save_cases_to_database(final_cases)
    except FileNotFoundError as error:
        print(f"File error: {error}")
        return 1
    except PermissionError as error:
        print(f"Permission error: {error}")
        return 1
    except sqlite3.Error as error:
        print(f"Database error: {error}")
        return 1
    except OSError as error:
        print(f"System error: {error}")
        return 1

    print()
    print("Done.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
