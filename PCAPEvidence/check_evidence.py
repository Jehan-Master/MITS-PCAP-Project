"""Small helper to inspect PCAP evidence stored in the shared SQLite DB."""

from __future__ import annotations

import argparse
import sqlite3
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", type=Path, default=Path("mits.db"))
    parser.add_argument("--case-id")
    parser.add_argument("--limit", type=int, default=20)
    args = parser.parse_args()

    if not args.db.is_file():
        print(f"Database not found: {args.db}")
        return 1

    with sqlite3.connect(args.db) as connection:
        connection.row_factory = sqlite3.Row
        exists = connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='pcap_evidence'"
        ).fetchone()
        if not exists:
            print("pcap_evidence table does not exist yet. Run PCAP Evidence first.")
            return 1

        total = connection.execute("SELECT COUNT(*) FROM pcap_evidence").fetchone()[0]
        print(f"PCAP evidence rows: {total:,}")

        sql = """
            SELECT case_id, pcap_file, packet_number, packet_time,
                   direction, src_ip, src_port, dest_ip, dest_port,
                   protocol, http_method, http_uri, http_status, dns_query
            FROM pcap_evidence
        """
        params: list[object] = []
        if args.case_id:
            sql += " WHERE case_id = ?"
            params.append(args.case_id)
        sql += " ORDER BY packet_epoch, packet_number LIMIT ?"
        params.append(args.limit)

        for row in connection.execute(sql, params):
            endpoint = f"{row['src_ip']}:{row['src_port']} -> {row['dest_ip']}:{row['dest_port']}"
            detail = ""
            if row["http_method"] or row["http_uri"]:
                detail = f" HTTP {row['http_method'] or ''} {row['http_uri'] or ''}".rstrip()
            elif row["http_status"]:
                detail = f" HTTP {row['http_status']}"
            elif row["dns_query"]:
                detail = f" DNS {row['dns_query']}"
            print(
                f"{row['case_id']} | {row['pcap_file']} frame {row['packet_number']} | "
                f"{row['packet_time']} | {endpoint} | {row['protocol']}{detail}"
            )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
