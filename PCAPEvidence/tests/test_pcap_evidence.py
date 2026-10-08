import json
import sqlite3
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from PCAPEvidence.pcap_evidence import (
    Case,
    FlowSelector,
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
        selector = FlowSelector(
            src_ip="80.94.95.211",
            src_port=53226,
            dest_ip="192.168.0.120",
            dest_port=80,
            protocol="TCP",
            first_seen=datetime(2026, 6, 20, 17, 11, 20, tzinfo=timezone.utc),
            last_seen=datetime(2026, 6, 20, 17, 11, 22, tzinfo=timezone.utc),
        )
        self.case = Case(
            case_id="CASE-0003",
            first_seen=selector.first_seen,
            last_seen=selector.last_seen,
            finding_ids=("R02-0003",),
            event_ids=(101, 102, 103),
            flow_ids=(100801491427561,),
            selectors=(selector,),
        )

    @staticmethod
    def create_current_pipeline_tables(connection):
        connection.executescript(
            """
            CREATE TABLE events (
                id INTEGER PRIMARY KEY,
                ts TEXT NOT NULL,
                event_type TEXT NOT NULL,
                flow_id INTEGER,
                src_ip TEXT,
                src_port INTEGER,
                dest_ip TEXT,
                dest_port INTEGER,
                proto TEXT
            );

            CREATE TABLE findings (
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

            CREATE TABLE cases (
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

            CREATE TABLE case_findings (
                case_id TEXT NOT NULL,
                finding_id TEXT NOT NULL,
                PRIMARY KEY(case_id, finding_id)
            );
            """
        )

    def insert_current_case(self, connection):
        connection.execute(
            """
            INSERT INTO cases VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                self.case.case_id,
                self.case.first_seen.isoformat(),
                self.case.last_seen.isoformat(),
                json.dumps(["80.94.95.211"]),
                json.dumps(["192.168.0.120"]),
                json.dumps(["R02-0003"]),
                json.dumps(["R02"]),
                1,
                "Single",
                json.dumps([]),
            ),
        )
        connection.execute(
            """
            INSERT INTO findings VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "R02-0003",
                "R02",
                "Multi-Port Activity",
                self.case.first_seen.isoformat(),
                "80.94.95.211",
                "test",
                "Medium",
                json.dumps([]),
                json.dumps([100801491427561]),
                json.dumps([]),
                json.dumps({}),
            ),
        )
        connection.execute(
            "INSERT INTO case_findings(case_id, finding_id) VALUES (?, ?)",
            (self.case.case_id, "R02-0003"),
        )
        connection.executemany(
            """
            INSERT INTO events(
                id, ts, event_type, flow_id, src_ip, src_port,
                dest_ip, dest_port, proto
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    101,
                    "2026-06-20T17:11:20+00:00",
                    "http",
                    100801491427561,
                    "80.94.95.211",
                    53226,
                    "192.168.0.120",
                    80,
                    "TCP",
                ),
                (
                    102,
                    "2026-06-20T17:11:21+00:00",
                    "http",
                    100801491427561,
                    "80.94.95.211",
                    53226,
                    "192.168.0.120",
                    80,
                    "TCP",
                ),
                (
                    103,
                    "2026-06-20T17:11:22+00:00",
                    "flow",
                    100801491427561,
                    "80.94.95.211",
                    53226,
                    "192.168.0.120",
                    80,
                    "TCP",
                ),
            ],
        )
        connection.commit()

    def test_filter_uses_current_event_tuple_and_both_directions(self):
        value = build_display_filter(self.case, 2.0)
        self.assertIn("tcp", value)
        self.assertIn("ip.src == 80.94.95.211", value)
        self.assertIn("ip.dst == 192.168.0.120", value)
        self.assertIn("tcp.srcport == 53226", value)
        self.assertIn("tcp.dstport == 80", value)
        self.assertIn("ip.src == 192.168.0.120", value)
        self.assertIn("ip.dst == 80.94.95.211", value)
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

    def test_current_pipeline_schema_loads_case_via_findings_and_events(self):
        connection = sqlite3.connect(":memory:")
        try:
            self.create_current_pipeline_tables(connection)
            self.insert_current_case(connection)
            validate_correlation_schema(connection)
            loaded = load_cases(connection, [self.case.case_id])
            self.assertEqual(len(loaded), 1)
            loaded_case = loaded[0]
            self.assertEqual(loaded_case.finding_ids, ("R02-0003",))
            self.assertEqual(loaded_case.flow_ids, (100801491427561,))
            self.assertEqual(loaded_case.event_ids, (101, 102, 103))
            self.assertEqual(len(loaded_case.selectors), 1)
            self.assertEqual(loaded_case.selectors[0].dest_port, 80)
        finally:
            connection.close()

    def test_case_event_links_resolve_finding_flow_ids_to_events(self):
        connection = sqlite3.connect(":memory:")
        try:
            self.create_current_pipeline_tables(connection)
            self.insert_current_case(connection)
            ensure_evidence_tables(connection)
            self.assertEqual(populate_case_event_links(connection), 3)
            rows = connection.execute(
                "SELECT case_id, event_id FROM case_eve_events ORDER BY event_id"
            ).fetchall()
            self.assertEqual(
                rows,
                [
                    (self.case.case_id, 101),
                    (self.case.case_id, 102),
                    (self.case.case_id, 103),
                ],
            )
            self.assertEqual(populate_case_event_links(connection), 0)
        finally:
            connection.close()

    def test_duplicate_packet_evidence_is_ignored(self):
        with tempfile.TemporaryDirectory() as directory:
            db = Path(directory) / "test.db"
            connection = sqlite3.connect(db)
            try:
                self.create_current_pipeline_tables(connection)
                self.insert_current_case(connection)
                ensure_evidence_tables(connection)
                packet = PacketEvidence(
                    packet_number=17,
                    packet_epoch=1781975481.0,
                    src_ip="80.94.95.211",
                    src_port=53226,
                    dest_ip="192.168.0.120",
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
            finally:
                connection.close()


if __name__ == "__main__":
    unittest.main()
