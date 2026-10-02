import sqlite3
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from PCAPEvidence.pcap_evidence import (
    Case,
    PacketEvidence,
    build_display_filter,
    candidate_pcaps_for_case,
    ensure_evidence_tables,
    load_cases,
    populate_case_event_links,
    save_packet_evidence,
    validate_correlation_schema,
)


class PCAPEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.case = Case(
            case_id="CASE-01443",
            src_ip="80.94.95.211",
            dest_ip="192.168.0.120",
            dest_port=80,
            protocol="TCP",
            first_seen=datetime(2026, 6, 20, 17, 11, 20, tzinfo=timezone.utc),
            last_seen=datetime(2026, 6, 20, 17, 12, 29, tzinfo=timezone.utc),
            flow_ids=(100801491427561, 680211652438194),
        )

    @staticmethod
    def create_correlation_tables(connection):
        connection.executescript(
            """
            CREATE TABLE cases (
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
            );
            CREATE TABLE case_flows (
                case_id TEXT NOT NULL,
                flow_id INTEGER NOT NULL,
                PRIMARY KEY(case_id, flow_id)
            );
            """
        )

    def test_filter_matches_correlation_grouping_and_both_directions(self):
        value = build_display_filter(self.case, 2.0)
        self.assertIn("tcp", value)
        self.assertIn("ip.src == 80.94.95.211", value)
        self.assertIn("ip.dst == 192.168.0.120", value)
        self.assertIn("tcp.dstport == 80", value)
        self.assertIn("ip.src == 192.168.0.120", value)
        self.assertIn("ip.dst == 80.94.95.211", value)
        self.assertIn("tcp.srcport == 80", value)
        self.assertIn("frame.time_epoch", value)

    def test_date_named_pcap_is_preferred(self):
        pcaps = [
            Path("capture.pcapng"),
            Path("2026-06-20.pcapng"),
            Path("2026-06-21.pcapng"),
        ]
        self.assertEqual(
            candidate_pcaps_for_case(self.case, pcaps),
            [Path("2026-06-20.pcapng")],
        )

    def test_exact_branch_schema_loads_case_and_flow_ids(self):
        connection = sqlite3.connect(":memory:")
        try:
            self.create_correlation_tables(connection)
            connection.execute(
                """
                INSERT INTO cases(
                    case_id, src_ip, dest_ip, dest_port, protocol,
                    first_seen, last_seen, duration_seconds,
                    flow_count, event_count, event_types
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    self.case.case_id,
                    self.case.src_ip,
                    self.case.dest_ip,
                    self.case.dest_port,
                    self.case.protocol,
                    self.case.first_seen.isoformat(),
                    self.case.last_seen.isoformat(),
                    69,
                    2,
                    60,
                    '{"http": 29, "fileinfo": 29, "flow": 2}',
                ),
            )
            connection.executemany(
                "INSERT INTO case_flows(case_id, flow_id) VALUES (?, ?)",
                [(self.case.case_id, flow_id) for flow_id in self.case.flow_ids],
            )
            validate_correlation_schema(connection)
            loaded = load_cases(connection, [self.case.case_id])
            self.assertEqual(len(loaded), 1)
            self.assertEqual(loaded[0].flow_ids, self.case.flow_ids)
        finally:
            connection.close()

    def test_case_event_links_use_shared_sqlite_events_table(self):
        connection = sqlite3.connect(":memory:")
        try:
            self.create_correlation_tables(connection)
            connection.execute(
                "INSERT INTO cases(case_id) VALUES (?)",
                (self.case.case_id,),
            )
            connection.executemany(
                "INSERT INTO case_flows(case_id, flow_id) VALUES (?, ?)",
                [(self.case.case_id, 123), (self.case.case_id, 456)],
            )
            connection.execute(
                "CREATE TABLE events(id INTEGER PRIMARY KEY, flow_id INTEGER)"
            )
            connection.executemany(
                "INSERT INTO events(id, flow_id) VALUES (?, ?)",
                [(1, 123), (2, 123), (3, 456), (4, 999)],
            )
            ensure_evidence_tables(connection)
            self.assertEqual(populate_case_event_links(connection), 3)
            rows = connection.execute(
                "SELECT case_id, event_id FROM case_eve_events ORDER BY event_id"
            ).fetchall()
            self.assertEqual(
                rows,
                [
                    (self.case.case_id, 1),
                    (self.case.case_id, 2),
                    (self.case.case_id, 3),
                ],
            )
        finally:
            connection.close()

    def test_duplicate_packet_evidence_is_ignored(self):
        with tempfile.TemporaryDirectory() as directory:
            db = Path(directory) / "test.db"
            with sqlite3.connect(db) as connection:
                self.create_correlation_tables(connection)
                connection.execute(
                    "INSERT INTO cases(case_id) VALUES (?)",
                    (self.case.case_id,),
                )
                ensure_evidence_tables(connection)
                packet = PacketEvidence(
                    packet_number=17,
                    packet_epoch=1781975481.0,
                    src_ip=self.case.src_ip,
                    src_port=53226,
                    dest_ip=self.case.dest_ip,
                    dest_port=80,
                    protocol="HTTP",
                    tcp_stream=5,
                    frame_length=110,
                    http_method="GET",
                    http_uri="/.env",
                    http_status=None,
                    dns_query=None,
                    is_retransmission=False,
                )
                pcap = Path(directory) / "2026-06-20.pcapng"
                pcap.touch()
                self.assertEqual(
                    save_packet_evidence(connection, self.case, pcap, [packet]), 1
                )
                self.assertEqual(
                    save_packet_evidence(connection, self.case, pcap, [packet]), 0
                )
                count = connection.execute(
                    "SELECT COUNT(*) FROM pcap_evidence"
                ).fetchone()[0]
                self.assertEqual(count, 1)


if __name__ == "__main__":
    unittest.main()
