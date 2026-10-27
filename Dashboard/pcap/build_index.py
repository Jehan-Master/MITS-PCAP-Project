import csv
import sqlite3
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
CSV_DIRECTORY = PROJECT_ROOT / "data" / "pcap_metadata"
DATABASE_DIRECTORY = PROJECT_ROOT / "data" / "pcap_index"
DATABASE_FILE = DATABASE_DIRECTORY / "pcap_metadata.db"

BATCH_SIZE = 10_000

EXPECTED_COLUMNS = {
    "pcap_filename",
    "frame_number",
    "timestamp_epoch",
    "src_ip",
    "src_port",
    "dest_ip",
    "dest_port",
    "protocols",
}


def create_database(connection):
    """Create the packet metadata table and search indexes."""
    connection.execute("""
        CREATE TABLE IF NOT EXISTS packet_metadata (
            id INTEGER PRIMARY KEY,
            pcap_filename TEXT NOT NULL,
            frame_number INTEGER NOT NULL,
            timestamp_epoch REAL NOT NULL,
            src_ip TEXT,
            src_port INTEGER,
            dest_ip TEXT,
            dest_port INTEGER,
            protocols TEXT NOT NULL,
            UNIQUE (pcap_filename, frame_number)
        )
    """)

    connection.execute("""
        CREATE INDEX IF NOT EXISTS idx_packet_five_tuple
        ON packet_metadata (
            src_ip, src_port, dest_ip, dest_port
        )
    """)

    connection.execute("""
        CREATE INDEX IF NOT EXISTS idx_packet_timestamp
        ON packet_metadata (timestamp_epoch)
    """)

    connection.execute("""
        CREATE INDEX IF NOT EXISTS idx_packet_protocol
        ON packet_metadata (protocols)
    """)


def optional_integer(value, field_name, row_number):
    """Convert a populated port to an integer."""
    value = value.strip()

    if not value:
        return None

    try:
        port = int(value)
    except ValueError as exc:
        raise ValueError(
            f"Invalid {field_name} at CSV row {row_number}: {value}"
        ) from exc

    if not 0 <= port <= 65535:
        raise ValueError(
            f"Out-of-range {field_name} at CSV row {row_number}: {value}"
        )

    return port


def import_csv(connection, csv_path):
    """Import one CSV in batches to limit memory usage."""
    inserted_count = 0
    batch = []

    with csv_path.open(
        "r", newline="", encoding="utf-8-sig"
    ) as csv_file:
        reader = csv.DictReader(csv_file)

        if not reader.fieldnames or not EXPECTED_COLUMNS.issubset(
            reader.fieldnames
        ):
            raise ValueError(
                f"Unexpected CSV columns in {csv_path.name}: "
                f"{reader.fieldnames}"
            )

        for row_number, row in enumerate(reader, start=2):
            try:
                frame_number = int(row["frame_number"])
                timestamp_epoch = float(row["timestamp_epoch"])

                if frame_number < 1:
                    raise ValueError("Frame number must be positive.")

                if not row["timestamp_epoch"].strip():
                    raise ValueError("Timestamp is empty.")

                src_ip = row["src_ip"].strip() or None
                dest_ip = row["dest_ip"].strip() or None
                protocols = row["protocols"].strip()

                if not protocols:
                    raise ValueError("Protocol stack is empty.")

                batch.append((
                    row["pcap_filename"],
                    frame_number,
                    timestamp_epoch,
                    src_ip,
                    optional_integer(
                        row["src_port"], "source port", row_number
                    ),
                    dest_ip,
                    optional_integer(
                        row["dest_port"], "destination port", row_number
                    ),
                    protocols,
                ))

            except (ValueError, TypeError) as exc:
                raise ValueError(
                    f"Invalid data in {csv_path.name}, "
                    f"CSV row {row_number}: {exc}"
                ) from exc

            if len(batch) >= BATCH_SIZE:
                connection.executemany("""
                    INSERT INTO packet_metadata (
                        pcap_filename,
                        frame_number,
                        timestamp_epoch,
                        src_ip,
                        src_port,
                        dest_ip,
                        dest_port,
                        protocols
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT (pcap_filename, frame_number)
                    DO UPDATE SET
                        timestamp_epoch = excluded.timestamp_epoch,
                        src_ip = excluded.src_ip,
                        src_port = excluded.src_port,
                        dest_ip = excluded.dest_ip,
                        dest_port = excluded.dest_port,
                        protocols = excluded.protocols
                """, batch)

                inserted_count += len(batch)
                batch.clear()

        if batch:
            connection.executemany("""
                INSERT INTO packet_metadata (
                    pcap_filename,
                    frame_number,
                    timestamp_epoch,
                    src_ip,
                    src_port,
                    dest_ip,
                    dest_port,
                    protocols
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT (pcap_filename, frame_number)
                DO UPDATE SET
                    timestamp_epoch = excluded.timestamp_epoch,
                    src_ip = excluded.src_ip,
                    src_port = excluded.src_port,
                    dest_ip = excluded.dest_ip,
                    dest_port = excluded.dest_port,
                    protocols = excluded.protocols
            """, batch)

            inserted_count += len(batch)

    return inserted_count


def main():
    if not CSV_DIRECTORY.is_dir():
        raise FileNotFoundError(
            f"Metadata directory not found: {CSV_DIRECTORY}"
        )

    csv_files = sorted(CSV_DIRECTORY.glob("*.csv"))

    if not csv_files:
        raise FileNotFoundError(
            f"No metadata CSV files found in {CSV_DIRECTORY}"
        )

    DATABASE_DIRECTORY.mkdir(parents=True, exist_ok=True)

    with sqlite3.connect(DATABASE_FILE) as connection:
        create_database(connection)

        for csv_path in csv_files:
            print(f"Importing {csv_path.name}...")

            count = import_csv(connection, csv_path)

            print(f"  Processed {count:,} rows.")

        connection.commit()

        total_rows = connection.execute(
            "SELECT COUNT(*) FROM packet_metadata"
        ).fetchone()[0]

        file_counts = connection.execute("""
            SELECT pcap_filename, COUNT(*)
            FROM packet_metadata
            GROUP BY pcap_filename
            ORDER BY pcap_filename
        """).fetchall()

    print("\nPCAP metadata index created.")
    print(f"Database: {DATABASE_FILE}")
    print(f"Total indexed packets: {total_rows:,}")

    for filename, count in file_counts:
        print(f"  {filename}: {count:,} packets")


if __name__ == "__main__":
    main()