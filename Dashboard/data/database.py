import sqlite3
from pathlib import Path

import pandas as pd
from project_paths import DATABASE_FILE


def get_connection():
    """Create a connection to the SQLite database."""
    return sqlite3.connect(DATABASE_FILE)


def get_events():
    """Load all events from the SQLite database."""
    connection = get_connection()

    try:
        events = pd.read_sql_query(
            """
            SELECT
                id,
                source_file,
                line_no,
                ts,
                event_type,
                flow_id,
                community_id,
                src_ip,
                src_port,
                dest_ip,
                dest_port,
                proto,
                app_proto,
                flow_start,
                flow_end,
                ssh_client_software,
                http_method,
                http_url,
                alert_sid,
                alert_signature,
                alert_severity
            FROM events
            ORDER BY ts
            """,
            connection,
        )

    finally:
        connection.close()

    events["ts"] = pd.to_datetime(
        events["ts"],
        errors="coerce",
    )

    return events
