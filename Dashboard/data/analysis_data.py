import json
import sqlite3
from project_paths import DATABASE_FILE

import pandas as pd

def get_connection():
    """Open a connection to the analysis database."""
    return sqlite3.connect(DATABASE_FILE)

def parse_json_list(value):
    """Convert a JSON list stored in SQLite into a Python list."""
    if not value:
        return []

    try:
        result = json.loads(value)

        if isinstance(result, list):
            return result

    except (json.JSONDecodeError, TypeError):
        pass

    return []

def get_cases():
    """Load candidate cases from the analysis database."""
    connection = get_connection()

    try:
        cases = pd.read_sql_query(
            """
            SELECT
                case_id,
                first_seen,
                last_seen,
                source_ips,
                destination_ips,
                finding_ids,
                rule_ids,
                finding_count,
                correlation_strength,
                correlation_reasons
            FROM cases
            ORDER BY first_seen
            """,
            connection,
        )

    finally:
        connection.close()

    list_columns = [
        "source_ips",
        "destination_ips",
        "finding_ids",
        "rule_ids",
        "correlation_reasons",
    ]

    for column in list_columns:
        cases[column] = cases[column].apply(parse_json_list)

    return cases

def get_case(case_id):
    """Load one candidate case from the analysis database."""
    connection = get_connection()

    try:
        case = pd.read_sql_query(
            """
            SELECT
                case_id,
                first_seen,
                last_seen,
                source_ips,
                destination_ips,
                finding_ids,
                rule_ids,
                finding_count,
                correlation_strength,
                correlation_reasons
            FROM cases
            WHERE case_id = ?
            """,
            connection,
            params=(case_id,),
        )
    finally:
        connection.close()

    if case.empty:
        return None

    list_columns = [
        "source_ips",
        "destination_ips",
        "finding_ids",
        "rule_ids",
        "correlation_reasons",
    ]

    for column in list_columns:
        case[column] = case[column].apply(parse_json_list)

    return case.iloc[0]

def get_findings():
    """Load detection findings from the analysis database."""
    connection = get_connection()

    try:
        findings = pd.read_sql_query(
            """
            SELECT
                finding_id,
                rule_id,
                rule_name,
                timestamp,
                source_ip,
                description,
                priority,
                event_ids,
                flow_ids,
                session_ids,
                details
            FROM findings
            ORDER BY timestamp
            """,
            connection,
        )
    finally:
        connection.close()

    list_columns = [
        "event_ids",
        "flow_ids",
        "session_ids",
    ]

    for column in list_columns:
        findings[column] = findings[column].apply(parse_json_list)

    return findings

def get_case_findings(case_id):
    """Load all detection findings belonging to a candidate case."""
    connection = get_connection()

    try:
        findings = pd.read_sql_query(
            """
            SELECT
                f.finding_id,
                f.rule_id,
                f.rule_name,
                f.timestamp,
                f.source_ip,
                f.description,
                f.priority,
                f.event_ids,
                f.flow_ids,
                f.session_ids,
                f.details
            FROM findings AS f
            INNER JOIN case_findings AS cf
                ON f.finding_id = cf.finding_id
            WHERE cf.case_id = ?
            ORDER BY f.timestamp
            """,
            connection,
            params=(case_id,),
        )
    finally:
        connection.close()

    list_columns = [
        "event_ids",
        "flow_ids",
        "session_ids",
    ]

    for column in list_columns:
        findings[column] = findings[column].apply(parse_json_list)

    return findings

def get_events_by_ids(event_ids):
    """Load EVE-JSON events by their database event IDs."""
    if not event_ids:
        return pd.DataFrame()

    connection = get_connection()

    try:
        placeholders = ",".join(
            "?" for _ in event_ids
        )

        events = pd.read_sql_query(
            f"""
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
            WHERE id IN ({placeholders})
            ORDER BY ts
            """,
            connection,
            params=event_ids,
        )

    finally:
        connection.close()

    return events

def get_events_by_flow_ids(flow_ids):
    """Load EVE-JSON events associated with the given flow IDs."""
    if not flow_ids:
        return pd.DataFrame()

    connection = get_connection()

    try:
        placeholders = ",".join("?" for _ in flow_ids)

        events = pd.read_sql_query(
            f"""
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
            WHERE flow_id IN ({placeholders})
            ORDER BY ts
            """,
            connection,
            params=list(flow_ids),
        )

    finally:
        connection.close()

    return events

def get_suricata_alerts():
    """Load EVE events that contain Suricata alert information."""
    connection = get_connection()

    try:
        alerts = pd.read_sql_query(
            """
            SELECT
                id,
                ts,
                src_ip,
                dest_ip,
                proto,
                alert_sid,
                alert_signature,
                alert_severity
            FROM events
            WHERE alert_sid IS NOT NULL
            ORDER BY ts
            """,
            connection,
        )
    finally:
        connection.close()

    return alerts
