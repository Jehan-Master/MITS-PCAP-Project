import sqlite3
from pathlib import Path

DATABASE_FILE = "mits.db"
SAMPLE_CASE_LIMIT = 5
FLOW_ID_LIMIT = 10


def get_record_count(connection, table_name):
    allowed_tables = {"cases", "case_flows"}
    if table_name not in allowed_tables:
        raise ValueError(f"Unsupported table name: {table_name}")

    cursor = connection.execute(f"SELECT COUNT(*) FROM {table_name}")
    return cursor.fetchone()[0]


def get_sample_cases(connection):
    cursor = connection.execute(
        """
        SELECT
            case_id,
            src_ip,
            dest_ip,
            dest_port,
            protocol,
            first_seen,
            last_seen,
            flow_count,
            event_count,
            event_types
        FROM cases
        ORDER BY flow_count DESC
        LIMIT ?
        """,
        (SAMPLE_CASE_LIMIT,),
    )
    return cursor.fetchall()


def get_flow_ids(connection, case_id):
    cursor = connection.execute(
        """
        SELECT flow_id
        FROM case_flows
        WHERE case_id = ?
        ORDER BY flow_id
        LIMIT ?
        """,
        (case_id, FLOW_ID_LIMIT),
    )
    return [row[0] for row in cursor.fetchall()]


def print_sample_case(case):
    print()
    print("--------------------------------------")
    print(f"Case ID:       {case['case_id']}")
    print(f"Source:        {case['src_ip']}")
    print(f"Destination:   {case['dest_ip']}:{case['dest_port']}")
    print(f"Protocol:      {case['protocol']}")
    print(f"First seen:    {case['first_seen']}")
    print(f"Last seen:     {case['last_seen']}")
    print(f"Flows:         {case['flow_count']}")
    print(f"Events:        {case['event_count']}")
    print(f"Event types:   {case['event_types']}")


def main():
    if not Path(DATABASE_FILE).is_file():
        print(f"Database file not found: {DATABASE_FILE}")
        return 1

    try:
        with sqlite3.connect(DATABASE_FILE) as connection:
            connection.row_factory = sqlite3.Row
            case_count = get_record_count(connection, "cases")
            case_flow_count = get_record_count(connection, "case_flows")
            sample_cases = get_sample_cases(connection)

            print("======================================")
            print("DATABASE CHECK")
            print("======================================")
            print(f"Cases stored:        {case_count:,}")
            print(f"Case-flow links:     {case_flow_count:,}")
            print()
            print("======================================")
            print("SAMPLE CASES")
            print("======================================")

            for case in sample_cases:
                print_sample_case(case)

            if sample_cases:
                example_case_id = sample_cases[0]["case_id"]
                flow_ids = get_flow_ids(connection, example_case_id)

                print()
                print("======================================")
                print("FLOW IDS FOR FIRST CASE")
                print("======================================")
                print(f"Case: {example_case_id}")
                print()

                for flow_id in flow_ids:
                    print(flow_id)
    except sqlite3.Error as error:
        print(f"Database error: {error}")
        return 1
    except OSError as error:
        print(f"System error: {error}")
        return 1

    print()
    print("Database check completed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
