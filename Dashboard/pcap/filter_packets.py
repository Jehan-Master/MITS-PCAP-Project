import sqlite3
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATABASE_FILE = (
    PROJECT_ROOT
    / "data"
    / "pcap_index"
    / "pcap_metadata.db"
)


def filter_packets(
    pcap_filename=None,
    src_ip=None,
    src_port=None,
    dest_ip=None,
    dest_port=None,
    protocol=None,
    start_epoch=None,
    end_epoch=None,
    limit=100,
):
    """Search indexed PCAP metadata using optional filter criteria."""
    if limit < 1:
        raise ValueError("limit must be at least 1")

    if (
        start_epoch is not None
        and end_epoch is not None
        and start_epoch > end_epoch
    ):
        raise ValueError("start_epoch must not exceed end_epoch")

    query = """
        SELECT
            pcap_filename,
            frame_number,
            timestamp_epoch,
            src_ip,
            src_port,
            dest_ip,
            dest_port,
            protocols
        FROM packet_metadata
        WHERE 1 = 1
    """
    parameters = []

    filters = {
        "pcap_filename": pcap_filename,
        "src_ip": src_ip,
        "src_port": src_port,
        "dest_ip": dest_ip,
        "dest_port": dest_port,
    }

    for column, value in filters.items():
        if value is not None:
            query += f" AND {column} = ?"
            parameters.append(value)

    if protocol is not None:
        query += " AND instr(':' || protocols || ':', ':' || ? || ':') > 0"
        parameters.append(protocol)

    if start_epoch is not None:
        query += " AND timestamp_epoch >= ?"
        parameters.append(start_epoch)

    if end_epoch is not None:
        query += " AND timestamp_epoch <= ?"
        parameters.append(end_epoch)

    query += """
        ORDER BY timestamp_epoch, frame_number
        LIMIT ?
    """
    parameters.append(limit)

    with sqlite3.connect(DATABASE_FILE) as connection:
        rows = connection.execute(
            query, parameters
        ).fetchall()

    return [
        {
            "pcap_filename": row[0],
            "frame_number": row[1],
            "timestamp_epoch": row[2],
            "src_ip": row[3],
            "src_port": row[4],
            "dest_ip": row[5],
            "dest_port": row[6],
            "protocols": row[7],
        }
        for row in rows
    ]