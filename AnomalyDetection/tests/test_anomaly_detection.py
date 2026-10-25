from __future__ import annotations

import sqlite3
import tempfile
from contextlib import closing
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from AnomalyDetection.anomaly_detection import parse_timestamp, run_analysis

EVENTS_SCHEMA = """
CREATE TABLE events (
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


def insert_event(
    connection: sqlite3.Connection,
    event_id: int,
    timestamp: datetime,
    src_ip: str,
    dest_ip: str,
    dest_port: int,
    flow_id: int,
    event_type: str = "flow",
) -> None:
    connection.execute(
        """
        INSERT INTO events (
            id, source_file, line_no, ts, event_type, flow_id,
            src_ip, src_port, dest_ip, dest_port, proto, raw
        ) VALUES (?, 'test.json', ?, ?, ?, ?, ?, 50000, ?, ?, 'TCP', '{}')
        """,
        (
            event_id,
            event_id,
            timestamp.strftime("%Y-%m-%dT%H:%M:%S.%f+0000"),
            event_type,
            flow_id,
            src_ip,
            dest_ip,
            dest_port,
        ),
    )


class AnomalyDetectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "mits.db"
        with closing(sqlite3.connect(self.db_path)) as connection:
            connection.executescript(EVENTS_SCHEMA)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_suricata_timestamp_is_parsed(self) -> None:
        parsed = parse_timestamp("2026-06-20T17:11:21.051956+0000")
        self.assertEqual(parsed.utcoffset(), timedelta(0))
        self.assertEqual(parsed.minute, 11)

    def test_burst_creates_structured_findings_and_event_links(self) -> None:
        start = datetime(2026, 6, 20, 12, 0, tzinfo=timezone.utc)
        event_id = 1

        with closing(sqlite3.connect(self.db_path)) as connection:
            # Ten normal one-minute windows: 3 events, one destination and one port.
            for minute in range(10):
                for index in range(3):
                    insert_event(
                        connection,
                        event_id,
                        start + timedelta(minutes=minute, seconds=index),
                        "203.0.113.10",
                        "192.168.0.120",
                        80,
                        flow_id=1000 + minute,
                    )
                    event_id += 1

            # One burst window: many events, flows, destinations and ports.
            burst_start = start + timedelta(minutes=10)
            for index in range(30):
                insert_event(
                    connection,
                    event_id,
                    burst_start + timedelta(seconds=index),
                    "203.0.113.10",
                    f"192.168.0.{100 + (index % 10)}",
                    1000 + index,
                    flow_id=5000 + index,
                )
                event_id += 1

            # Another source provides normal global observations.
            for minute in range(11):
                for index in range(2):
                    insert_event(
                        connection,
                        event_id,
                        start + timedelta(minutes=minute, seconds=20 + index),
                        "198.51.100.20",
                        "192.168.0.120",
                        443,
                        flow_id=8000 + minute,
                    )
                    event_id += 1
            connection.commit()

        result = run_analysis(self.db_path, threshold=3.5, min_source_windows=5)
        self.assertGreater(result.findings_created, 0)
        self.assertGreater(result.event_links_created, 0)

        with closing(sqlite3.connect(self.db_path)) as connection:
            metrics = {
                row[0]
                for row in connection.execute(
                    "SELECT metric FROM anomaly_findings WHERE src_ip='203.0.113.10'"
                )
            }
            self.assertIn("event_count", metrics)
            self.assertIn("unique_destination_ports", metrics)

            status = connection.execute(
                "SELECT DISTINCT status FROM anomaly_findings"
            ).fetchall()
            self.assertEqual(status, [("candidate_for_investigation",)])

    def test_normal_repeated_behaviour_does_not_create_findings(self) -> None:
        start = datetime(2026, 6, 20, 12, 0, tzinfo=timezone.utc)
        event_id = 1
        with closing(sqlite3.connect(self.db_path)) as connection:
            for minute in range(12):
                for index in range(3):
                    insert_event(
                        connection,
                        event_id,
                        start + timedelta(minutes=minute, seconds=index),
                        "203.0.113.10",
                        "192.168.0.120",
                        80,
                        flow_id=1000 + minute,
                    )
                    event_id += 1
            connection.commit()

        result = run_analysis(self.db_path, threshold=3.5, min_source_windows=5)
        self.assertEqual(result.findings_created, 0)
        self.assertEqual(result.event_links_created, 0)

    def test_rerun_does_not_duplicate_findings_or_links(self) -> None:
        start = datetime(2026, 6, 20, 12, 0, tzinfo=timezone.utc)
        event_id = 1
        with closing(sqlite3.connect(self.db_path)) as connection:
            for minute in range(6):
                count = 3 if minute < 5 else 25
                for index in range(count):
                    insert_event(
                        connection,
                        event_id,
                        start + timedelta(minutes=minute, seconds=index),
                        "203.0.113.10",
                        "192.168.0.120",
                        80 + index,
                        flow_id=1000 + event_id,
                    )
                    event_id += 1
            connection.commit()

        run_analysis(self.db_path, threshold=3.5, min_source_windows=5)
        with closing(sqlite3.connect(self.db_path)) as connection:
            first_findings = connection.execute(
                "SELECT COUNT(*) FROM anomaly_findings"
            ).fetchone()[0]
            first_links = connection.execute(
                "SELECT COUNT(*) FROM anomaly_events"
            ).fetchone()[0]

        run_analysis(self.db_path, threshold=3.5, min_source_windows=5)
        with closing(sqlite3.connect(self.db_path)) as connection:
            second_findings = connection.execute(
                "SELECT COUNT(*) FROM anomaly_findings"
            ).fetchone()[0]
            second_links = connection.execute(
                "SELECT COUNT(*) FROM anomaly_events"
            ).fetchone()[0]

        self.assertEqual(first_findings, second_findings)
        self.assertEqual(first_links, second_links)


if __name__ == "__main__":
    unittest.main()
