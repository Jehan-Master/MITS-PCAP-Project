import sqlite3

DATABASE_FILE = "mits.db"


def create_database_tables(connection):
    cursor = connection.cursor()

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS cases (
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
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS case_flows (
            case_id TEXT NOT NULL,
            flow_id INTEGER NOT NULL,
            PRIMARY KEY (case_id, flow_id),
            FOREIGN KEY (case_id) REFERENCES cases(case_id)
        )
        """
    )

    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_cases_source
        ON cases(src_ip)
        """
    )
    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_cases_destination
        ON cases(dest_ip, dest_port)
        """
    )
    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_case_flows_flow_id
        ON case_flows(flow_id)
        """
    )


def get_table_names(connection):
    cursor = connection.execute(
        """
        SELECT name
        FROM sqlite_master
        WHERE type = 'table'
        ORDER BY name
        """
    )
    return [row[0] for row in cursor.fetchall()]


def main():
    print("Creating database...")

    try:
        with sqlite3.connect(DATABASE_FILE) as connection:
            connection.execute("PRAGMA foreign_keys = ON")
            create_database_tables(connection)
            table_names = get_table_names(connection)
    except sqlite3.Error as error:
        print(f"Database error: {error}")
        return 1
    except OSError as error:
        print(f"System error: {error}")
        return 1

    print()
    print("Database created successfully.")
    print(f"Database file: {DATABASE_FILE}")
    print()
    print("Tables:")

    for table_name in table_names:
        print(f"- {table_name}")

    print()
    print("Done.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
