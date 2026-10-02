"""Connect correlated MITS cases to packet-level PCAP evidence.

This module is intentionally built around the SQLite contract produced by the
correlation branch:

    cases(case_id, src_ip, dest_ip, dest_port, protocol, first_seen, last_seen, ...)
    case_flows(case_id, flow_id)

If the ingestion ``events`` table is present in the same SQLite database, the
module also creates case -> EVE event links by joining ``case_flows.flow_id`` to
``events.flow_id``.

Raw PCAP files do not contain Suricata ``flow_id`` values, so packet matching is
performed using the correlated case's endpoints, destination/service port,
protocol and time window. TShark is used to read PCAP/PCAPNG files.
"""

from __future__ import annotations

import argparse
import csv
import io
import shutil
import sqlite3
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Sequence

DEFAULT_PADDING_SECONDS = 2.0

REQUIRED_CASE_COLUMNS = {
    "case_id",
    "src_ip",
    "dest_ip",
    "dest_port",
    "protocol",
    "first_seen",
    "last_seen",
}
REQUIRED_CASE_FLOW_COLUMNS = {"case_id", "flow_id"}

TSHARK_FIELDS = (
    "frame.number",
    "frame.time_epoch",
    "ip.src",
    "ipv6.src",
    "ip.dst",
    "ipv6.dst",
    "tcp.srcport",
    "udp.srcport",
    "tcp.dstport",
    "udp.dstport",
    "_ws.col.Protocol",
    "tcp.stream",
    "http.request.method",
    "http.request.uri",
    "http.response.code",
    "dns.qry.name",
    "frame.len",
    "tcp.analysis.retransmission",
)

EVIDENCE_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS pcap_evidence (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id           TEXT    NOT NULL,
    pcap_file         TEXT    NOT NULL,
    pcap_path         TEXT    NOT NULL,
    packet_number     INTEGER NOT NULL,
    packet_time       TEXT    NOT NULL,
    packet_epoch      REAL    NOT NULL,
    direction         TEXT,
    src_ip            TEXT,
    src_port          INTEGER,
    dest_ip           TEXT,
    dest_port         INTEGER,
    protocol          TEXT,
    tcp_stream        INTEGER,
    frame_length      INTEGER,
    http_method       TEXT,
    http_uri          TEXT,
    http_status       INTEGER,
    dns_query         TEXT,
    is_retransmission INTEGER NOT NULL DEFAULT 0,
    created_at        TEXT    NOT NULL,
    UNIQUE (case_id, pcap_path, packet_number),
    FOREIGN KEY (case_id) REFERENCES cases(case_id)
);

CREATE TABLE IF NOT EXISTS case_eve_events (
    case_id  TEXT    NOT NULL,
    event_id INTEGER NOT NULL,
    PRIMARY KEY (case_id, event_id),
    FOREIGN KEY (case_id) REFERENCES cases(case_id)
);

CREATE INDEX IF NOT EXISTS idx_pcap_evidence_case
ON pcap_evidence(case_id);

CREATE INDEX IF NOT EXISTS idx_pcap_evidence_time
ON pcap_evidence(packet_epoch);

CREATE INDEX IF NOT EXISTS idx_pcap_evidence_endpoints
ON pcap_evidence(src_ip, dest_ip, dest_port);

CREATE INDEX IF NOT EXISTS idx_case_eve_events_event
ON case_eve_events(event_id);
"""

INSERT_EVIDENCE_SQL = """
INSERT OR IGNORE INTO pcap_evidence (
    case_id,
    pcap_file,
    pcap_path,
    packet_number,
    packet_time,
    packet_epoch,
    direction,
    src_ip,
    src_port,
    dest_ip,
    dest_port,
    protocol,
    tcp_stream,
    frame_length,
    http_method,
    http_uri,
    http_status,
    dns_query,
    is_retransmission,
    created_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
"""


@dataclass(frozen=True)
class Case:
    case_id: str
    src_ip: str
    dest_ip: str
    dest_port: int | None
    protocol: str | None
    first_seen: datetime
    last_seen: datetime
    flow_ids: tuple[int, ...]


@dataclass(frozen=True)
class PacketEvidence:
    packet_number: int
    packet_epoch: float
    src_ip: str | None
    src_port: int | None
    dest_ip: str | None
    dest_port: int | None
    protocol: str | None
    tcp_stream: int | None
    frame_length: int | None
    http_method: str | None
    http_uri: str | None
    http_status: int | None
    dns_query: str | None
    is_retransmission: bool


def parse_timestamp(value: str) -> datetime:
    """Parse ISO timestamps used by Suricata and the correlation script."""
    value = value.strip()
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    if len(value) >= 5 and value[-5] in ("+", "-") and value[-3] != ":":
        value = value[:-2] + ":" + value[-2:]

    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def iso_from_epoch(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()


def table_exists(connection: sqlite3.Connection, table_name: str) -> bool:
    return (
        connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
            (table_name,),
        ).fetchone()
        is not None
    )


def table_columns(connection: sqlite3.Connection, table_name: str) -> set[str]:
    return {
        row[1]
        for row in connection.execute(f'PRAGMA table_info("{table_name}")').fetchall()
    }


def validate_correlation_schema(connection: sqlite3.Connection) -> None:
    """Validate the exact minimum SQLite contract Task 4 needs."""
    if not table_exists(connection, "cases"):
        raise RuntimeError("Missing required SQLite table: cases")
    if not table_exists(connection, "case_flows"):
        raise RuntimeError("Missing required SQLite table: case_flows")

    missing_cases = REQUIRED_CASE_COLUMNS - table_columns(connection, "cases")
    missing_case_flows = REQUIRED_CASE_FLOW_COLUMNS - table_columns(
        connection, "case_flows"
    )
    if missing_cases:
        raise RuntimeError(
            "cases table is missing required columns: "
            + ", ".join(sorted(missing_cases))
        )
    if missing_case_flows:
        raise RuntimeError(
            "case_flows table is missing required columns: "
            + ", ".join(sorted(missing_case_flows))
        )


def ensure_evidence_tables(connection: sqlite3.Connection) -> None:
    connection.executescript(EVIDENCE_SCHEMA_SQL)
    connection.commit()


def populate_case_event_links(connection: sqlite3.Connection) -> int:
    """Link cases to ingested EVE rows when ``events`` exists in the same DB.

    This is the future shared-SQLite integration point. The current correlation
    branch already stores ``case_flows``. Once ingestion and correlation use the
    same database, this join makes the EVE evidence traceable without rereading
    the raw JSON file.
    """
    if not table_exists(connection, "events"):
        return 0

    event_columns = table_columns(connection, "events")
    if not {"id", "flow_id"}.issubset(event_columns):
        raise RuntimeError("events table must contain id and flow_id columns")

    before = connection.total_changes
    connection.execute(
        """
        INSERT OR IGNORE INTO case_eve_events (case_id, event_id)
        SELECT cf.case_id, e.id
        FROM case_flows AS cf
        JOIN events AS e ON e.flow_id = cf.flow_id
        WHERE e.flow_id IS NOT NULL
        """
    )
    connection.commit()
    return connection.total_changes - before


def load_cases(
    connection: sqlite3.Connection,
    case_ids: Sequence[str] | None = None,
    limit: int | None = None,
) -> list[Case]:
    validate_correlation_schema(connection)

    sql = """
        SELECT
            case_id,
            src_ip,
            dest_ip,
            dest_port,
            protocol,
            first_seen,
            last_seen
        FROM cases
    """
    parameters: list[object] = []

    if case_ids:
        placeholders = ", ".join("?" for _ in case_ids)
        sql += f" WHERE case_id IN ({placeholders})"
        parameters.extend(case_ids)

    sql += " ORDER BY first_seen, case_id"
    if limit is not None:
        sql += " LIMIT ?"
        parameters.append(limit)

    rows = connection.execute(sql, parameters).fetchall()
    result: list[Case] = []

    for row in rows:
        flow_ids = tuple(
            item[0]
            for item in connection.execute(
                """
                SELECT flow_id
                FROM case_flows
                WHERE case_id = ?
                ORDER BY flow_id
                """,
                (row[0],),
            ).fetchall()
        )

        if not row[1] or not row[2] or not row[5] or not row[6]:
            print(
                f"Warning: skipping {row[0]} because endpoint/time data is incomplete.",
                file=sys.stderr,
            )
            continue

        result.append(
            Case(
                case_id=row[0],
                src_ip=row[1],
                dest_ip=row[2],
                dest_port=row[3],
                protocol=row[4],
                first_seen=parse_timestamp(row[5]),
                last_seen=parse_timestamp(row[6]),
                flow_ids=flow_ids,
            )
        )

    return result


def _address_fields(ip: str) -> tuple[str, str]:
    if ":" in ip:
        return "ipv6.src", "ipv6.dst"
    return "ip.src", "ip.dst"


def build_display_filter(case: Case, padding_seconds: float) -> str:
    """Create a bidirectional TShark display filter for one case.

    ``flow_id`` cannot be used because it is generated by Suricata and is not a
    field stored in raw PCAP packets. The filter therefore uses the same tuple
    the correlation groups by: source, destination, destination/service port,
    protocol and time.
    """
    if (":" in case.src_ip) != (":" in case.dest_ip):
        raise ValueError(f"{case.case_id} mixes IPv4 and IPv6 endpoints")

    src_source_field, src_dest_field = _address_fields(case.src_ip)
    dst_source_field, dst_dest_field = _address_fields(case.dest_ip)

    start_epoch = case.first_seen.timestamp() - padding_seconds
    end_epoch = case.last_seen.timestamp() + padding_seconds

    protocol = (case.protocol or "").strip().lower()
    if protocol == "tcp":
        protocol_clause = "tcp"
        forward_port = (
            f" && tcp.dstport == {case.dest_port}"
            if case.dest_port is not None
            else ""
        )
        reverse_port = (
            f" && tcp.srcport == {case.dest_port}"
            if case.dest_port is not None
            else ""
        )
    elif protocol == "udp":
        protocol_clause = "udp"
        forward_port = (
            f" && udp.dstport == {case.dest_port}"
            if case.dest_port is not None
            else ""
        )
        reverse_port = (
            f" && udp.srcport == {case.dest_port}"
            if case.dest_port is not None
            else ""
        )
    else:
        protocol_clause = protocol
        forward_port = ""
        reverse_port = ""

    forward = (
        f"({src_source_field} == {case.src_ip} && "
        f"{dst_dest_field} == {case.dest_ip}{forward_port})"
    )
    reverse = (
        f"({dst_source_field} == {case.dest_ip} && "
        f"{src_dest_field} == {case.src_ip}{reverse_port})"
    )

    endpoint_clause = f"({forward} || {reverse})"
    time_clause = (
        f"frame.time_epoch >= {start_epoch:.6f} && "
        f"frame.time_epoch <= {end_epoch:.6f}"
    )

    clauses = [endpoint_clause, time_clause]
    if protocol_clause:
        clauses.insert(0, protocol_clause)
    return " && ".join(clauses)


def find_tshark(explicit_path: str | None) -> str:
    if explicit_path:
        candidate = Path(explicit_path)
        if candidate.is_file():
            return str(candidate)
        resolved = shutil.which(explicit_path)
        if resolved:
            return resolved
        raise FileNotFoundError(f"TShark not found: {explicit_path}")

    found = shutil.which("tshark")
    if found:
        return found

    windows_default = Path(r"C:\Program Files\Wireshark\tshark.exe")
    if windows_default.is_file():
        return str(windows_default)

    raise FileNotFoundError(
        "TShark was not found. Install Wireshark or pass --tshark with the full path."
    )


def collect_pcaps(pcap_paths: Iterable[Path], pcap_dirs: Iterable[Path]) -> list[Path]:
    files: dict[Path, None] = {}

    for path in pcap_paths:
        resolved = path.expanduser().resolve()
        if not resolved.is_file():
            raise FileNotFoundError(f"PCAP file not found: {path}")
        files[resolved] = None

    for directory in pcap_dirs:
        resolved_dir = directory.expanduser().resolve()
        if not resolved_dir.is_dir():
            raise FileNotFoundError(f"PCAP directory not found: {directory}")
        for pattern in ("*.pcap", "*.pcapng"):
            for path in resolved_dir.rglob(pattern):
                if path.is_file():
                    files[path.resolve()] = None

    if not files:
        raise FileNotFoundError("No .pcap or .pcapng files were supplied/found")

    return sorted(files)


def candidate_pcaps_for_case(case: Case, pcaps: Sequence[Path]) -> list[Path]:
    """Prefer a capture whose filename contains the case's UTC date."""
    case_date = case.first_seen.astimezone(timezone.utc).date().isoformat()
    dated = [path for path in pcaps if case_date in path.name]
    return dated or list(pcaps)


def _empty_to_none(value: str) -> str | None:
    value = value.strip()
    return value if value else None


def _int_or_none(value: str) -> int | None:
    value = value.strip()
    if not value:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def parse_tshark_output(output: str) -> list[PacketEvidence]:
    rows = csv.reader(io.StringIO(output), delimiter="\t", quotechar='"')
    packets: list[PacketEvidence] = []

    for row in rows:
        if not row:
            continue
        if len(row) < len(TSHARK_FIELDS):
            row.extend([""] * (len(TSHARK_FIELDS) - len(row)))

        frame_number = _int_or_none(row[0])
        try:
            epoch = float(row[1])
        except ValueError:
            continue
        if frame_number is None:
            continue

        src_ip = _empty_to_none(row[2]) or _empty_to_none(row[3])
        dest_ip = _empty_to_none(row[4]) or _empty_to_none(row[5])
        src_port = _int_or_none(row[6]) or _int_or_none(row[7])
        dest_port = _int_or_none(row[8]) or _int_or_none(row[9])

        packets.append(
            PacketEvidence(
                packet_number=frame_number,
                packet_epoch=epoch,
                src_ip=src_ip,
                src_port=src_port,
                dest_ip=dest_ip,
                dest_port=dest_port,
                protocol=_empty_to_none(row[10]),
                tcp_stream=_int_or_none(row[11]),
                http_method=_empty_to_none(row[12]),
                http_uri=_empty_to_none(row[13]),
                http_status=_int_or_none(row[14]),
                dns_query=_empty_to_none(row[15]),
                frame_length=_int_or_none(row[16]),
                is_retransmission=bool(_empty_to_none(row[17])),
            )
        )

    return packets


def extract_packet_metadata(
    tshark: str,
    pcap: Path,
    display_filter: str,
) -> list[PacketEvidence]:
    command = [
        tshark,
        "-n",
        "-r",
        str(pcap),
        "-Y",
        display_filter,
        "-T",
        "fields",
        "-E",
        "header=n",
        "-E",
        "separator=/t",
        "-E",
        "quote=d",
        "-E",
        "occurrence=f",
    ]
    for field in TSHARK_FIELDS:
        command.extend(["-e", field])

    completed = subprocess.run(
        command,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if completed.returncode != 0:
        message = completed.stderr.strip() or "Unknown TShark error"
        raise RuntimeError(f"TShark failed for {pcap.name}: {message}")

    return parse_tshark_output(completed.stdout)


def packet_direction(case: Case, packet: PacketEvidence) -> str | None:
    if packet.src_ip == case.src_ip and packet.dest_ip == case.dest_ip:
        return "source_to_destination"
    if packet.src_ip == case.dest_ip and packet.dest_ip == case.src_ip:
        return "destination_to_source"
    return None


def save_packet_evidence(
    connection: sqlite3.Connection,
    case: Case,
    pcap: Path,
    packets: Sequence[PacketEvidence],
) -> int:
    created_at = datetime.now(tz=timezone.utc).isoformat()
    resolved_path = str(pcap.expanduser().resolve())

    rows = [
        (
            case.case_id,
            pcap.name,
            resolved_path,
            packet.packet_number,
            iso_from_epoch(packet.packet_epoch),
            packet.packet_epoch,
            packet_direction(case, packet),
            packet.src_ip,
            packet.src_port,
            packet.dest_ip,
            packet.dest_port,
            packet.protocol,
            packet.tcp_stream,
            packet.frame_length,
            packet.http_method,
            packet.http_uri,
            packet.http_status,
            packet.dns_query,
            1 if packet.is_retransmission else 0,
            created_at,
        )
        for packet in packets
    ]

    if not rows:
        return 0

    before = connection.total_changes
    connection.executemany(INSERT_EVIDENCE_SQL, rows)
    connection.commit()
    return connection.total_changes - before


def export_case_capture(
    tshark: str,
    pcap: Path,
    display_filter: str,
    case_id: str,
    output_directory: Path,
) -> Path:
    output_directory.mkdir(parents=True, exist_ok=True)
    output_path = output_directory / f"{case_id}__{pcap.stem}.pcapng"

    command = [
        tshark,
        "-n",
        "-r",
        str(pcap),
        "-Y",
        display_filter,
        "-w",
        str(output_path),
    ]
    completed = subprocess.run(
        command,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if completed.returncode != 0:
        message = completed.stderr.strip() or "Unknown TShark error"
        raise RuntimeError(f"Could not export {case_id}: {message}")
    return output_path


def process_cases(
    connection: sqlite3.Connection,
    cases: Sequence[Case],
    pcaps: Sequence[Path],
    tshark: str,
    padding_seconds: float,
    export_directory: Path | None,
) -> tuple[int, int]:
    total_matches = 0
    total_new_rows = 0

    for index, case in enumerate(cases, start=1):
        print(
            f"[{index}/{len(cases)}] {case.case_id}: "
            f"{case.src_ip} -> {case.dest_ip}:{case.dest_port} "
            f"({case.protocol or 'unknown'}, {len(case.flow_ids)} flows)"
        )
        display_filter = build_display_filter(case, padding_seconds)
        case_matches = 0
        case_new_rows = 0

        for pcap in candidate_pcaps_for_case(case, pcaps):
            packets = extract_packet_metadata(tshark, pcap, display_filter)
            if not packets:
                continue

            case_matches += len(packets)
            new_rows = save_packet_evidence(connection, case, pcap, packets)
            case_new_rows += new_rows
            print(
                f"  {pcap.name}: {len(packets):,} matching packets, "
                f"{new_rows:,} new evidence rows"
            )

            if export_directory is not None:
                exported = export_case_capture(
                    tshark,
                    pcap,
                    display_filter,
                    case.case_id,
                    export_directory,
                )
                print(f"  exported: {exported}")

        if case_matches == 0:
            print("  no matching packets found")

        total_matches += case_matches
        total_new_rows += case_new_rows

    return total_matches, total_new_rows


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Connect correlated SQLite cases to packet-level PCAP evidence using TShark."
        )
    )
    parser.add_argument(
        "--db",
        type=Path,
        default=Path("mits.db"),
        help="shared SQLite database (default: mits.db)",
    )
    parser.add_argument(
        "--pcap",
        type=Path,
        action="append",
        default=[],
        help="PCAP/PCAPNG file; may be supplied multiple times",
    )
    parser.add_argument(
        "--pcap-dir",
        type=Path,
        action="append",
        default=[],
        help="directory containing PCAP/PCAPNG files; searched recursively",
    )
    parser.add_argument(
        "--tshark",
        help="path to tshark.exe/tshark; auto-detected when omitted",
    )
    parser.add_argument(
        "--case-id",
        action="append",
        default=[],
        help="process only this case ID; may be supplied multiple times",
    )
    parser.add_argument(
        "--limit",
        type=int,
        help="process only the first N selected cases (useful for testing)",
    )
    parser.add_argument(
        "--time-padding",
        type=float,
        default=DEFAULT_PADDING_SECONDS,
        help=(
            "seconds added before/after each case window "
            f"(default: {DEFAULT_PADDING_SECONDS})"
        ),
    )
    parser.add_argument(
        "--export-dir",
        type=Path,
        help="optional directory for per-case PCAPNG evidence files",
    )
    parser.add_argument(
        "--show-filter",
        action="store_true",
        help="print the TShark filter for each selected case before processing",
    )
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()

    if not arguments.db.is_file():
        print(f"Database file not found: {arguments.db}", file=sys.stderr)
        return 1
    if arguments.limit is not None and arguments.limit < 1:
        print("--limit must be at least 1", file=sys.stderr)
        return 1
    if arguments.time_padding < 0:
        print("--time-padding cannot be negative", file=sys.stderr)
        return 1

    try:
        pcaps = collect_pcaps(arguments.pcap, arguments.pcap_dir)
        tshark = find_tshark(arguments.tshark)
    except (FileNotFoundError, ValueError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1

    print("======================================")
    print("MITS PCAP EVIDENCE")
    print("======================================")
    print(f"Database:       {arguments.db}")
    print(f"TShark:         {tshark}")
    print(f"PCAP files:     {len(pcaps)}")
    print(f"Time padding:   {arguments.time_padding} seconds")
    print()

    try:
        with sqlite3.connect(arguments.db) as connection:
            connection.execute("PRAGMA foreign_keys = ON")
            validate_correlation_schema(connection)
            ensure_evidence_tables(connection)

            linked_events = populate_case_event_links(connection)
            if table_exists(connection, "events"):
                total_case_event_links = connection.execute(
                    "SELECT COUNT(*) FROM case_eve_events"
                ).fetchone()[0]
                print(
                    f"Case -> EVE links: {total_case_event_links:,} total "
                    f"({linked_events:,} new)"
                )
            else:
                print(
                    "events table not present yet; PCAP evidence will still be "
                    "linked to cases. Once ingestion uses this same SQLite DB, "
                    "case -> EVE links will be created automatically."
                )

            cases = load_cases(
                connection,
                case_ids=arguments.case_id or None,
                limit=arguments.limit,
            )
            if not cases:
                print("No matching cases found")
                return 0

            print(f"Cases selected: {len(cases):,}")
            if arguments.show_filter:
                for case in cases:
                    print(f"{case.case_id}: {build_display_filter(case, arguments.time_padding)}")
                print()

            matches, new_rows = process_cases(
                connection=connection,
                cases=cases,
                pcaps=pcaps,
                tshark=tshark,
                padding_seconds=arguments.time_padding,
                export_directory=arguments.export_dir,
            )

            total_rows = connection.execute(
                "SELECT COUNT(*) FROM pcap_evidence"
            ).fetchone()[0]
    except (sqlite3.Error, RuntimeError, ValueError, OSError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1

    print()
    print("======================================")
    print("DONE")
    print("======================================")
    print(f"Matching packets:    {matches:,}")
    print(f"New evidence rows:   {new_rows:,}")
    print(f"Evidence rows total: {total_rows:,}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
