import argparse
import base64
import hashlib
import ipaddress
import sqlite3
import sys
import time
from collections import Counter
from pathlib import Path

import orjson

EXCLUDED_EVENT_TYPES = {"stats", "mdns", "dhcp"}
BATCH_SIZE = 10000
PROGRESS_EVERY_LINES = 1000000
COMMUNITY_ID_SEED = 0
PROTOCOL_NUMBERS = {"TCP": 6, "UDP": 17, "SCTP": 132}

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS events (
    id                  INTEGER PRIMARY KEY,
    source_file         TEXT    NOT NULL,
    line_no             INTEGER NOT NULL,
    ts                  TEXT    NOT NULL,
    event_type          TEXT    NOT NULL,
    flow_id             INTEGER,
    community_id        TEXT,
    src_ip              TEXT,
    src_port            INTEGER,
    dest_ip             TEXT,
    dest_port           INTEGER,
    proto               TEXT,
    app_proto           TEXT,
    flow_start          TEXT,
    flow_end            TEXT,
    ssh_client_software TEXT,
    http_method         TEXT,
    http_url            TEXT,
    alert_sid           INTEGER,
    alert_signature     TEXT,
    alert_severity      INTEGER,
    raw                 TEXT    NOT NULL,
    UNIQUE (source_file, line_no)
);
"""

INDEX_SQL = """
CREATE INDEX IF NOT EXISTS idx_events_flow_id      ON events (flow_id);
CREATE INDEX IF NOT EXISTS idx_events_community_id ON events (community_id);
CREATE INDEX IF NOT EXISTS idx_events_src_ip       ON events (src_ip);
CREATE INDEX IF NOT EXISTS idx_events_ts           ON events (ts);
CREATE INDEX IF NOT EXISTS idx_events_event_type   ON events (event_type);
"""

INSERT_SQL = """
INSERT OR IGNORE INTO events (
    source_file, line_no, ts, event_type, flow_id, community_id,
    src_ip, src_port, dest_ip, dest_port, proto, app_proto,
    flow_start, flow_end, ssh_client_software, http_method, http_url,
    alert_sid, alert_signature, alert_severity, raw
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
"""


def compute_community_id(src_ip, src_port, dest_ip, dest_port, proto):
    protocol_number = PROTOCOL_NUMBERS.get(proto)
    if protocol_number is None or None in (src_ip, src_port, dest_ip, dest_port):
        return None

    try:
        src_address = ipaddress.ip_address(src_ip).packed
        dest_address = ipaddress.ip_address(dest_ip).packed
    except ValueError:
        return None

    if (src_address, src_port) > (dest_address, dest_port):
        src_address, dest_address = dest_address, src_address
        src_port, dest_port = dest_port, src_port

    hash_input = (
        COMMUNITY_ID_SEED.to_bytes(2, "big")
        + src_address
        + dest_address
        + bytes([protocol_number, 0])
        + src_port.to_bytes(2, "big")
        + dest_port.to_bytes(2, "big")
    )
    digest = hashlib.sha1(hash_input).digest()
    return "1:" + base64.b64encode(digest).decode("ascii")


def build_row(event, source_file, line_no, raw_line):
    flow = event.get("flow") or {}
    ssh_client = (event.get("ssh") or {}).get("client") or {}
    http = event.get("http") or {}
    alert = event.get("alert") or {}

    return (
        source_file,
        line_no,
        event["timestamp"],
        event["event_type"],
        event.get("flow_id"),
        compute_community_id(
            event.get("src_ip"),
            event.get("src_port"),
            event.get("dest_ip"),
            event.get("dest_port"),
            event.get("proto"),
        ),
        event.get("src_ip"),
        event.get("src_port"),
        event.get("dest_ip"),
        event.get("dest_port"),
        event.get("proto"),
        event.get("app_proto"),
        flow.get("start"),
        flow.get("end"),
        ssh_client.get("software_version"),
        http.get("http_method"),
        http.get("url"),
        alert.get("signature_id"),
        alert.get("signature"),
        alert.get("severity"),
        raw_line,
    )


def insert_batch(connection, batch):
    changes_before = connection.total_changes
    connection.executemany(INSERT_SQL, batch)
    connection.commit()
    return connection.total_changes - changes_before


def ingest_file(connection, path):
    stored_types = Counter()
    skipped_types = Counter()
    malformed_lines = 0
    new_rows = 0
    batch = []

    with path.open("rb") as eve_file:
        for line_no, line in enumerate(eve_file, start=1):
            if line_no % PROGRESS_EVERY_LINES == 0:
                print(f"  ...{line_no:,} lines read", file=sys.stderr)

            line = line.strip()
            if not line:
                continue

            try:
                event = orjson.loads(line)
            except orjson.JSONDecodeError:
                malformed_lines += 1
                continue

            if not isinstance(event, dict) or "timestamp" not in event:
                malformed_lines += 1
                continue

            event_type = event.get("event_type")
            if event_type is None:
                malformed_lines += 1
                continue
            if event_type in EXCLUDED_EVENT_TYPES:
                skipped_types[event_type] += 1
                continue

            raw_line = line.decode("utf-8", errors="replace")
            batch.append(build_row(event, path.name, line_no, raw_line))
            stored_types[event_type] += 1

            if len(batch) >= BATCH_SIZE:
                new_rows += insert_batch(connection, batch)
                batch = []

    if batch:
        new_rows += insert_batch(connection, batch)

    return stored_types, skipped_types, malformed_lines, new_rows


def open_database(db_path):
    connection = sqlite3.connect(db_path)
    connection.execute("PRAGMA journal_mode = WAL")
    connection.execute("PRAGMA synchronous = NORMAL")
    connection.executescript(SCHEMA_SQL)
    return connection


def print_summary(path, stored_types, skipped_types, malformed_lines, new_rows, seconds):
    stored_total = sum(stored_types.values())
    skipped_total = sum(skipped_types.values())
    already_present = stored_total - new_rows

    print(f"{path.name}  ({seconds:.1f}s)")
    print(f"  stored:    {new_rows:,} new rows"
          + (f" ({already_present:,} were already in the database)" if already_present else ""))
    print("  by type:   " + ", ".join(f"{name} {count:,}" for name, count in stored_types.most_common()))
    skipped_detail = ", ".join(f"{name} {count:,}" for name, count in skipped_types.most_common())
    print(f"  skipped:   {skipped_total:,}" + (f" ({skipped_detail})" if skipped_detail else ""))
    print(f"  malformed: {malformed_lines:,} lines")


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Load Suricata eve.json files into the shared MITS SQLite database."
    )
    parser.add_argument("inputs", nargs="+", type=Path, help="one or more eve.json files")
    parser.add_argument("--db", type=Path, default=Path("mits.db"),
                        help="path to the SQLite database (default: mits.db)")
    return parser.parse_args()


def main():
    arguments = parse_arguments()

    missing_files = [path for path in arguments.inputs if not path.is_file()]
    if missing_files:
        for path in missing_files:
            print(f"Error: input file not found: {path}", file=sys.stderr)
        return 1

    connection = open_database(arguments.db)
    try:
        for path in arguments.inputs:
            start_time = time.perf_counter()
            results = ingest_file(connection, path)
            print_summary(path, *results, time.perf_counter() - start_time)

        print("Building indexes...")
        connection.executescript(INDEX_SQL)
    finally:
        connection.close()

    print(f"Done. Database: {arguments.db}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
