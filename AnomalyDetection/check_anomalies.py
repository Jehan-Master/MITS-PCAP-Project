from __future__ import annotations

import argparse
from contextlib import closing
from pathlib import Path

try:
    from .database import connect, table_exists
except ImportError:
    from database import connect, table_exists  


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Inspect stored anomaly findings.")
    parser.add_argument("--db", type=Path, default=Path("mits.db"))
    parser.add_argument("--source", help="optional source IP filter")
    parser.add_argument("--limit", type=int, default=20)
    return parser.parse_args()


def main() -> int:
    args = parse_arguments()
    if not args.db.is_file():
        print(f"Database not found: {args.db}")
        return 1

    with closing(connect(args.db)) as connection:
        if not table_exists(connection, "anomaly_findings"):
            print("No anomaly_findings table. Run anomaly detection first.")
            return 1

        sql = """
        SELECT f.finding_id, f.window_start, f.src_ip, f.metric,
               f.observed_value, f.baseline_median, f.anomaly_score,
               f.baseline_scope, f.status,
               COUNT(e.event_id) AS supporting_events
        FROM anomaly_findings AS f
        LEFT JOIN anomaly_events AS e ON e.finding_id = f.finding_id
        """
        params: list[object] = []
        if args.source:
            sql += " WHERE f.src_ip = ?"
            params.append(args.source)
        sql += """
        GROUP BY f.finding_id
        ORDER BY f.anomaly_score DESC
        LIMIT ?
        """
        params.append(args.limit)

        rows = connection.execute(sql, params).fetchall()

    if not rows:
        print("No matching anomaly findings.")
        return 0

    for row in rows:
        print(
            f"{row['finding_id']} | {row['src_ip']} | {row['window_start']} | "
            f"{row['metric']}={row['observed_value']:.0f} | "
            f"baseline={row['baseline_median']:.2f} | "
            f"score={row['anomaly_score']:.2f} | "
            f"evidence events={row['supporting_events']} | {row['status']}"
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
