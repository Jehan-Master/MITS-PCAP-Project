"""Connect correlated MITS cases to packet-level PCAP evidence.

The current MITS pipeline stores case relationships as::

    cases
      -> case_findings
      -> findings(event_ids, flow_ids)
      -> events

Raw PCAP/PCAPNG files do not contain Suricata ``flow_id`` values.  This module
therefore resolves each case back to its supporting EVE events, derives the
network tuples and time windows from those events, and asks TShark for the
matching packets.  Packet references are then stored in the same SQLite
database so the dashboard can trace a case back to both EVE and PCAP evidence.
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import shutil
import sqlite3
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Sequence

DEFAULT_PADDING_SECONDS = 2.0
SQLITE_IN_CHUNK = 900

# Windows' CreateProcess has a hard ~32,767 character command-line limit, and
# raises WinError 206 ("The filename or extension is too long") once the
# combined argv length goes over it. Cases with many flows build very long
# "-Y" display filters (one OR'd clause per packet selector), so filters are
# split into batches that stay comfortably under that limit on every OS.
MAX_DISPLAY_FILTER_LENGTH = 6000

REQUIRED_TABLE_COLUMNS = {
    "cases": {"case_id", "first_seen", "last_seen"},
    "case_findings": {"case_id", "finding_id"},
    "findings": {"finding_id", "event_ids", "flow_ids"},
    "events": {
        "id",
        "ts",
        "flow_id",
        "src_ip",
        "src_port",
        "dest_ip",
        "dest_port",
        "proto",
    },
}

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
    FOREIGN KEY (case_id) REFERENCES cases(case_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS case_eve_events (
    case_id  TEXT    NOT NULL,
    event_id INTEGER NOT NULL,
    PRIMARY KEY (case_id, event_id),
    FOREIGN KEY (case_id) REFERENCES cases(case_id) ON DELETE CASCADE,
    FOREIGN KEY (event_id) REFERENCES events(id) ON DELETE CASCADE
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
class FlowSelector:
    """One network tuple/time range that supports a correlated case."""

    src_ip: str
    src_port: int | None
    dest_ip: str
    dest_port: int | None
    protocol: str | None
    first_seen: datetime
    last_seen: datetime


@dataclass(frozen=True)
class Case:
    case_id: str
    first_seen: datetime
    last_seen: datetime
    finding_ids: tuple[str, ...]
    event_ids: tuple[int, ...]
    flow_ids: tuple[int, ...]
    selectors: tuple[FlowSelector, ...]


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
    """Parse ISO timestamps used by Suricata/pandas and normalize to UTC-aware."""
    value = str(value).strip()
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
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
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
    """Validate the SQLite contract produced by the current analysis pipeline."""
    for table_name, required_columns in REQUIRED_TABLE_COLUMNS.items():
        if not table_exists(connection, table_name):
            raise RuntimeError(f"Missing required SQLite table: {table_name}")
        missing = required_columns - table_columns(connection, table_name)
        if missing:
            raise RuntimeError(
                f"{table_name} table is missing required columns: "
                + ", ".join(sorted(missing))
            )


def ensure_evidence_tables(connection: sqlite3.Connection) -> None:
    connection.executescript(EVIDENCE_SCHEMA_SQL)
    connection.commit()


def _parse_int_list(raw_value: object) -> list[int]:
    """Read an ID list persisted as JSON; tolerate stringified numeric IDs."""
    if raw_value is None:
        return []
    if isinstance(raw_value, (list, tuple)):
        values = raw_value
    else:
        try:
            values = json.loads(str(raw_value))
        except (json.JSONDecodeError, TypeError):
            return []

    if not isinstance(values, list):
        return []

    result: list[int] = []
    for value in values:
        try:
            result.append(int(value))
        except (TypeError, ValueError):
            continue
    return result


def _chunks(values: Sequence[int], size: int = SQLITE_IN_CHUNK):
    for index in range(0, len(values), size):
        yield values[index:index + size]


def _case_references(
    connection: sqlite3.Connection,
    case_id: str,
) -> tuple[tuple[str, ...], tuple[int, ...], tuple[int, ...]]:
    """Return finding, event and flow IDs supporting one case."""
    rows = connection.execute(
        """
        SELECT f.finding_id, f.event_ids, f.flow_ids
        FROM case_findings AS cf
        JOIN findings AS f ON f.finding_id = cf.finding_id
        WHERE cf.case_id = ?
        ORDER BY f.finding_id
        """,
        (case_id,),
    ).fetchall()

    finding_ids: list[str] = []
    event_ids: set[int] = set()
    flow_ids: set[int] = set()
    for finding_id, raw_event_ids, raw_flow_ids in rows:
        finding_ids.append(str(finding_id))
        event_ids.update(_parse_int_list(raw_event_ids))
        flow_ids.update(_parse_int_list(raw_flow_ids))

    return (
        tuple(finding_ids),
        tuple(sorted(event_ids)),
        tuple(sorted(flow_ids)),
    )


def _load_supporting_events(
    connection: sqlite3.Connection,
    event_ids: Sequence[int],
    flow_ids: Sequence[int],
) -> list[sqlite3.Row]:
    """Resolve finding references to the concrete EVE rows needed for PCAP filters."""
    previous_factory = connection.row_factory
    connection.row_factory = sqlite3.Row
    events: dict[int, sqlite3.Row] = {}
    try:
        for chunk in _chunks(list(event_ids)):
            placeholders = ",".join("?" for _ in chunk)
            for row in connection.execute(
                f"""
                SELECT id, ts, flow_id, src_ip, src_port, dest_ip, dest_port, proto
                FROM events
                WHERE id IN ({placeholders})
                """,
                chunk,
            ):
                events[int(row["id"])] = row

        for chunk in _chunks(list(flow_ids)):
            placeholders = ",".join("?" for _ in chunk)
            for row in connection.execute(
                f"""
                SELECT id, ts, flow_id, src_ip, src_port, dest_ip, dest_port, proto
                FROM events
                WHERE flow_id IN ({placeholders})
                """,
                chunk,
            ):
                events[int(row["id"])] = row
    finally:
        connection.row_factory = previous_factory

    return sorted(events.values(), key=lambda row: (str(row["ts"]), int(row["id"])))


def _selectors_from_events(rows: Sequence[sqlite3.Row]) -> tuple[FlowSelector, ...]:
    """Collapse supporting EVE rows into unique network tuples with time ranges."""
    groups: dict[tuple[object, ...], dict[str, object]] = {}

    for row in rows:
        if not row["ts"] or not row["src_ip"] or not row["dest_ip"]:
            continue

        try:
            timestamp = parse_timestamp(row["ts"])
        except (ValueError, TypeError):
            continue

        key = (
            str(row["src_ip"]),
            row["src_port"],
            str(row["dest_ip"]),
            row["dest_port"],
            str(row["proto"]) if row["proto"] else None,
        )
        existing = groups.get(key)
        if existing is None:
            groups[key] = {"first_seen": timestamp, "last_seen": timestamp}
        else:
            existing["first_seen"] = min(existing["first_seen"], timestamp)
            existing["last_seen"] = max(existing["last_seen"], timestamp)

    selectors = [
        FlowSelector(
            src_ip=key[0],
            src_port=key[1],
            dest_ip=key[2],
            dest_port=key[3],
            protocol=key[4],
            first_seen=value["first_seen"],
            last_seen=value["last_seen"],
        )
        for key, value in groups.items()
    ]
    selectors.sort(
        key=lambda selector: (
            selector.first_seen,
            selector.src_ip,
            selector.dest_ip,
            selector.src_port or -1,
            selector.dest_port or -1,
        )
    )
    return tuple(selectors)


def load_cases(
    connection: sqlite3.Connection,
    case_ids: Sequence[str] | None = None,
    limit: int | None = None,
) -> list[Case]:
    """Load cases and resolve their findings back to EVE network tuples."""
    validate_correlation_schema(connection)

    sql = "SELECT case_id, first_seen, last_seen FROM cases"
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

    for case_id, first_seen_raw, last_seen_raw in rows:
        finding_ids, direct_event_ids, flow_ids = _case_references(connection, case_id)
        supporting_events = _load_supporting_events(
            connection,
            direct_event_ids,
            flow_ids,
        )
        resolved_event_ids = tuple(sorted(int(row["id"]) for row in supporting_events))
        selectors = _selectors_from_events(supporting_events)

        if not finding_ids:
            print(
                f"Warning: skipping {case_id}; it has no linked findings.",
                file=sys.stderr,
            )
            continue
        if not selectors:
            print(
                f"Warning: skipping {case_id}; supporting findings did not resolve "
                "to usable event endpoint/time data.",
                file=sys.stderr,
            )
            continue

        result.append(
            Case(
                case_id=str(case_id),
                first_seen=parse_timestamp(first_seen_raw),
                last_seen=parse_timestamp(last_seen_raw),
                finding_ids=finding_ids,
                event_ids=resolved_event_ids,
                flow_ids=flow_ids,
                selectors=selectors,
            )
        )

    return result


def populate_case_event_links(connection: sqlite3.Connection) -> int:
    """Persist case -> EVE links derived from case findings and finding flow IDs."""
    validate_correlation_schema(connection)
    before = connection.total_changes

    case_ids = [row[0] for row in connection.execute("SELECT case_id FROM cases")]
    rows: list[tuple[str, int]] = []
    for case_id in case_ids:
        _, event_ids, flow_ids = _case_references(connection, case_id)
        supporting_events = _load_supporting_events(connection, event_ids, flow_ids)
        rows.extend((str(case_id), int(row["id"])) for row in supporting_events)

    connection.executemany(
        "INSERT OR IGNORE INTO case_eve_events(case_id, event_id) VALUES (?, ?)",
        rows,
    )
    connection.commit()
    return connection.total_changes - before


def _address_fields(ip: str) -> tuple[str, str]:
    if ":" in ip:
        return "ipv6.src", "ipv6.dst"
    return "ip.src", "ip.dst"


def _selector_filter(selector: FlowSelector, padding_seconds: float) -> str:
    if (":" in selector.src_ip) != (":" in selector.dest_ip):
        raise ValueError("A selector mixes IPv4 and IPv6 endpoints")

    src_source_field, src_dest_field = _address_fields(selector.src_ip)
    dst_source_field, dst_dest_field = _address_fields(selector.dest_ip)

    protocol = (selector.protocol or "").strip().lower()
    protocol_clause = ""
    if protocol == "tcp":
        protocol_clause = "tcp"
        src_port_field = "tcp.srcport"
        dest_port_field = "tcp.dstport"
    elif protocol == "udp":
        protocol_clause = "udp"
        src_port_field = "udp.srcport"
        dest_port_field = "udp.dstport"
    else:
        src_port_field = None
        dest_port_field = None
        if protocol:
            protocol_clause = protocol

    forward_parts = [
        f"{src_source_field} == {selector.src_ip}",
        f"{dst_dest_field} == {selector.dest_ip}",
    ]
    reverse_parts = [
        f"{dst_source_field} == {selector.dest_ip}",
        f"{src_dest_field} == {selector.src_ip}",
    ]

    if src_port_field and selector.src_port is not None:
        forward_parts.append(f"{src_port_field} == {selector.src_port}")
        reverse_parts.append(f"{dest_port_field} == {selector.src_port}")
    if dest_port_field and selector.dest_port is not None:
        forward_parts.append(f"{dest_port_field} == {selector.dest_port}")
        reverse_parts.append(f"{src_port_field} == {selector.dest_port}")

    start_epoch = selector.first_seen.timestamp() - padding_seconds
    end_epoch = selector.last_seen.timestamp() + padding_seconds
    endpoint_clause = (
        f"(({' && '.join(forward_parts)}) || ({' && '.join(reverse_parts)}))"
    )
    time_clause = (
        f"frame.time_epoch >= {start_epoch:.6f} && "
        f"frame.time_epoch <= {end_epoch:.6f}"
    )
    parts = [endpoint_clause, time_clause]
    if protocol_clause:
        parts.insert(0, protocol_clause)
    return " && ".join(parts)


def build_display_filter(case: Case, padding_seconds: float) -> str:
    """Build a case filter as the OR of its supporting event network tuples."""
    if not case.selectors:
        raise ValueError(f"{case.case_id} has no usable packet selectors")
    selector_filters = [
        f"({_selector_filter(selector, padding_seconds)})"
        for selector in case.selectors
    ]
    return " || ".join(selector_filters)


def build_display_filter_batches(
    case: Case,
    padding_seconds: float,
    max_length: int = MAX_DISPLAY_FILTER_LENGTH,
) -> list[str]:
    """Build one or more display filters for a case, each under max_length.

    Cases with many flows produce a very long OR'd display filter (one clause
    per packet selector). A single filter that long can exceed the host OS's
    command-line length limit when handed to TShark as a subprocess argument
    (WinError 206 on Windows). This splits the selectors into batches so each
    resulting filter string stays under max_length, while still covering
    every selector across the returned batches.
    """
    if not case.selectors:
        raise ValueError(f"{case.case_id} has no usable packet selectors")

    clauses = [
        f"({_selector_filter(selector, padding_seconds)})"
        for selector in case.selectors
    ]

    batches: list[str] = []
    current: list[str] = []
    current_length = 0

    for clause in clauses:
        # +4 approximates the " || " joiner that will sit between clauses.
        added_length = len(clause) + (4 if current else 0)
        if current and current_length + added_length > max_length:
            batches.append(" || ".join(current))
            current = []
            current_length = 0
            added_length = len(clause)

        current.append(clause)
        current_length += added_length

    if current:
        batches.append(" || ".join(current))

    return batches


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
    """Prefer captures whose filename contains the case's UTC date."""
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


def _packet_matches_selector(packet: PacketEvidence, selector: FlowSelector) -> str | None:
    if packet.src_ip == selector.src_ip and packet.dest_ip == selector.dest_ip:
        if selector.src_port is not None and packet.src_port != selector.src_port:
            return None
        if selector.dest_port is not None and packet.dest_port != selector.dest_port:
            return None
        return "source_to_destination"

    if packet.src_ip == selector.dest_ip and packet.dest_ip == selector.src_ip:
        if selector.dest_port is not None and packet.src_port != selector.dest_port:
            return None
        if selector.src_port is not None and packet.dest_port != selector.src_port:
            return None
        return "destination_to_source"
    return None


def packet_direction(case: Case, packet: PacketEvidence) -> str | None:
    for selector in case.selectors:
        direction = _packet_matches_selector(packet, selector)
        if direction:
            return direction
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
            f"{len(case.finding_ids)} findings, {len(case.flow_ids)} flows, "
            f"{len(case.event_ids)} EVE events, {len(case.selectors)} packet selectors"
        )
        display_filter_batches = build_display_filter_batches(
            case, padding_seconds
        )
        if len(display_filter_batches) > 1:
            print(
                f"  filter split into {len(display_filter_batches)} batches "
                "(too many selectors for a single TShark command line)"
            )
        case_matches = 0
        case_new_rows = 0

        for pcap in candidate_pcaps_for_case(case, pcaps):
            packets_by_frame: dict[int, PacketEvidence] = {}
            for display_filter in display_filter_batches:
                for packet in extract_packet_metadata(
                    tshark, pcap, display_filter
                ):
                    packets_by_frame[packet.packet_number] = packet
            packets = sorted(
                packets_by_frame.values(), key=lambda p: p.packet_number
            )
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
                for batch_index, display_filter in enumerate(
                    display_filter_batches, start=1
                ):
                    suffix = (
                        case.case_id
                        if len(display_filter_batches) == 1
                        else f"{case.case_id}-part{batch_index}"
                    )
                    exported = export_case_capture(
                        tshark,
                        pcap,
                        display_filter,
                        suffix,
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
            "Connect current MITS SQLite cases to packet-level PCAP evidence using TShark."
        )
    )
    parser.add_argument(
        "--db",
        type=Path,
        default=Path("database") / "mits_test.db",
        help="shared SQLite database (default: database/mits_test.db)",
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
            "seconds added before/after supporting event windows "
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
            total_case_event_links = connection.execute(
                "SELECT COUNT(*) FROM case_eve_events"
            ).fetchone()[0]
            print(
                f"Case -> EVE links: {total_case_event_links:,} total "
                f"({linked_events:,} new)"
            )

            cases = load_cases(
                connection,
                case_ids=arguments.case_id or None,
                limit=arguments.limit,
            )
            if not cases:
                print("No matching cases with usable packet evidence references found")
                return 0

            print(f"Cases selected: {len(cases):,}")
            if arguments.show_filter:
                for case in cases:
                    batches = build_display_filter_batches(
                        case, arguments.time_padding
                    )
                    if len(batches) == 1:
                        print(f"{case.case_id}: {batches[0]}")
                    else:
                        print(
                            f"{case.case_id} "
                            f"({len(batches)} filter batches):"
                        )
                        for index, batch in enumerate(batches, start=1):
                            print(f"  part {index}: {batch}")
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