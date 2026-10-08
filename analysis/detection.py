import sqlite3
from pathlib import Path

import pandas as pd
import ipaddress


DATABASE_PATH = (
    Path(__file__).resolve().parent.parent
    / "database"
    / "mits_test.db"
)

HIGH_CONNECTION_THRESHOLD = 20
HIGH_CONNECTION_WINDOW_SECONDS = 60

MULTI_PORT_THRESHOLD = 3
MULTI_PORT_WINDOW_SECONDS = 60

FAILED_AUTH_THRESHOLD = 3
FAILED_AUTH_WINDOW_SECONDS = 10

PROTOCOL_ANOMALY_THRESHOLD = 2
PROTOCOL_ANOMALY_WINDOW_SECONDS = 60

INTERNAL_NETWORKS = [
    ipaddress.ip_network("192.168.0.0/24"),
]

def get_connection(database_path=DATABASE_PATH):
    """Create a connection to the selected project SQLite database."""
    return sqlite3.connect(database_path)


def load_events(database_path=DATABASE_PATH):
    """Load relevant event data from the selected SQLite database."""
    connection = get_connection(database_path)

    try:
        events = pd.read_sql_query(
            """
            SELECT
                id,
                ts,
                event_type,
                flow_id,
                src_ip,
                src_port,
                dest_ip,
                dest_port,
                proto,
                app_proto,
                ssh_client_software,
                raw
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


def create_finding(
    rule_id,
    rule_name,
    timestamp,
    source_ip,
    description,
    priority,
    event_ids=None,
    flow_ids=None,
    session_ids=None,
    details=None,
):
    """Create a standardized detection finding."""
    return {
        "rule_id": rule_id,
        "rule_name": rule_name,
        "timestamp": timestamp,
        "source_ip": source_ip,
        "description": description,
        "priority": priority,
        "event_ids": event_ids or [],
        "flow_ids": flow_ids or [],
        "session_ids": session_ids or [],
        "details": details or {},
    }

def detect_high_connection_rate(events):
    """Detect sources generating many flows within a short time window."""
    findings = []

    flow_events = events[
        events["flow_id"].notna()
        & events["src_ip"].notna()
    ].copy()

    # Keep one record per flow.
    flows = (
        flow_events
        .sort_values("ts")
        .drop_duplicates(subset=["flow_id"])
    )

    for source_ip, source_flows in flows.groupby("src_ip"):
        source_flows = source_flows.sort_values("ts").reset_index(
            drop=True
        )

        for start_index in range(len(source_flows)):
            window_start = source_flows.loc[start_index, "ts"]
            window_end = (
                window_start
                + pd.Timedelta(
                    seconds=HIGH_CONNECTION_WINDOW_SECONDS
                )
            )

            window = source_flows[
                (source_flows["ts"] >= window_start)
                & (source_flows["ts"] <= window_end)
            ]

            flow_count = len(window)

            if flow_count >= HIGH_CONNECTION_THRESHOLD:
                findings.append(
                    create_finding(
                        rule_id="R01",
                        rule_name="High Connection Rate",
                        timestamp=window_start,
                        source_ip=source_ip,
                        description=(
                            f"Source generated {flow_count} flows "
                            f"within {HIGH_CONNECTION_WINDOW_SECONDS} "
                            "seconds."
                        ),
                        priority="Medium",
                        flow_ids=window["flow_id"].tolist(),
                        details={
                            "flow_count": flow_count,
                            "window_start": window_start,
                            "window_end": window["ts"].max(),
                            "destination_ips": (
                                window["dest_ip"]
                                .dropna()
                                .unique()
                                .tolist()
                            ),
                        },
                    )
                )

    return findings

def consolidate_high_connection_findings(findings):
    """Combine overlapping high connection rate findings."""
    if not findings:
        return []

    consolidated = []

    findings = sorted(
        findings,
        key=lambda finding: (
            finding["source_ip"],
            finding["timestamp"],
        ),
    )

    current_episode = None

    for finding in findings:
        source_ip = finding["source_ip"]
        window_start = finding["timestamp"]
        window_end = finding["details"]["window_end"]

        if current_episode is None:
            current_episode = {
                "source_ip": source_ip,
                "start": window_start,
                "end": window_end,
                "max_flow_count": finding["details"]["flow_count"],
                "max_flow_timestamp": window_start,
                "flow_ids": set(finding["flow_ids"]),
                "destination_ips": set(finding["details"]["destination_ips"]),
            }
            continue

        same_source = (
            source_ip == current_episode["source_ip"]
        )

        overlaps_episode = (
            window_start <= current_episode["end"]
        )

        if same_source and overlaps_episode:
            current_episode["end"] = max(
                current_episode["end"],
                window_end,
            )

            current_episode["flow_ids"].update(
                finding["flow_ids"]
            )

            current_episode["destination_ips"].update(
                finding["details"]["destination_ips"]
            )

            if (
                finding["details"]["flow_count"]
                > current_episode["max_flow_count"]
            ):
                current_episode["max_flow_count"] = (
                    finding["details"]["flow_count"]
                )
                current_episode["max_flow_timestamp"] = (
                    window_start
                )

        else:
            consolidated.append(current_episode)

            current_episode = {
                "source_ip": source_ip,
                "start": window_start,
                "end": window_end,
                "max_flow_count": finding["details"]["flow_count"],
                "max_flow_timestamp": window_start,
                "flow_ids": set(finding["flow_ids"]),
                "destination_ips": set(finding["details"]["destination_ips"]),
            }

    consolidated.append(current_episode)

    return consolidated

def build_high_connection_findings(events):
    """Detect and consolidate high connection rate episodes."""
    raw_findings = detect_high_connection_rate(events)

    episodes = consolidate_high_connection_findings(
        raw_findings
    )

    findings = []

    for index, episode in enumerate(episodes, start=1):
        source_ip = episode["source_ip"]

        findings.append(
            create_finding(
                rule_id="R01",
                rule_name="High Connection Rate",
                timestamp=episode["start"],
                source_ip=source_ip,
                description=(
                    f"Source repeatedly exceeded the threshold "
                    f"of {HIGH_CONNECTION_THRESHOLD} flows "
                    f"within {HIGH_CONNECTION_WINDOW_SECONDS} "
                    "seconds."
                ),
                priority="Medium",
                flow_ids=sorted(
                    episode["flow_ids"]
                ),
                details={
                    "episode_id": f"R01-{index:04d}",
                    "episode_start": episode["start"],
                    "episode_end": episode["end"],
                    "max_flow_count": (
                        episode["max_flow_count"]
                    ),
                    "max_flow_timestamp": (
                        episode["max_flow_timestamp"]
                    ),
                    "total_flows": len(
                        episode["flow_ids"]
                    ),
                    "destination_ips": sorted(
                        episode["destination_ips"]
                    ),
                },
            )
        )

    return findings

def is_internal_ip(ip_address):
    """Return whether an IP belongs to a configured internal network."""
    if not ip_address:
        return False

    try:
        ip = ipaddress.ip_address(ip_address)
    except ValueError:
        return False

    return any(
        ip in network
        for network in INTERNAL_NETWORKS
    )

def detect_multi_port_activity(events):
    """Detect sources contacting multiple destination ports quickly."""
    findings = []

    flow_events = events[
        events["flow_id"].notna()
        & events["src_ip"].notna()
        & events["dest_ip"].notna()
        & events["dest_port"].notna()
    ].copy()
    
    flow_events = flow_events[
        ~flow_events["src_ip"].apply(is_internal_ip)
        & flow_events["dest_ip"].apply(is_internal_ip)
    ].copy()

    # Keep one record per flow.
    flows = (
        flow_events
        .sort_values("ts")
        .drop_duplicates(subset=["flow_id"])
    )

    for source_ip, source_flows in flows.groupby("src_ip"):
        source_flows = source_flows.sort_values("ts").reset_index(
            drop=True
        )

        for start_index in range(len(source_flows)):
            window_start = source_flows.loc[start_index, "ts"]
            window_end = (
                window_start
                + pd.Timedelta(
                    seconds=MULTI_PORT_WINDOW_SECONDS
                )
            )

            window = source_flows[
                (source_flows["ts"] >= window_start)
                & (source_flows["ts"] <= window_end)
            ]

            destination_ports = sorted(
                int(port)
                for port in window["dest_port"].dropna().unique()
            )

            port_count = len(destination_ports)

            if port_count >= MULTI_PORT_THRESHOLD:
                findings.append(
                    create_finding(
                        rule_id="R02",
                        rule_name="Multi-Port Activity",
                        timestamp=window_start,
                        source_ip=source_ip,
                        description=(
                            f"Source contacted {port_count} "
                            f"distinct destination ports within "
                            f"{MULTI_PORT_WINDOW_SECONDS} seconds."
                        ),
                        priority="Medium",
                        flow_ids=window["flow_id"].tolist(),
                        details={
                            "port_count": port_count,
                            "destination_ports": destination_ports,
                            "destination_ips": (
                                window["dest_ip"]
                                .dropna()
                                .unique()
                                .tolist()
                            ),
                            "window_start": window_start,
                            "window_end": window["ts"].max(),
                        },
                    )
                )

    return findings

def consolidate_multi_port_findings(findings):
    """Combine overlapping multi-port activity findings."""
    if not findings:
        return []

    consolidated = []

    findings = sorted(
        findings,
        key=lambda finding: (
            finding["source_ip"],
            finding["timestamp"],
        ),
    )

    current_episode = None

    for finding in findings:
        source_ip = finding["source_ip"]
        window_start = finding["timestamp"]
        window_end = finding["details"]["window_end"]

        if current_episode is None:
            current_episode = {
                "source_ip": source_ip,
                "start": window_start,
                "end": window_end,
                "max_port_count": (
                    finding["details"]["port_count"]
                ),
                "max_port_timestamp": window_start,
                "destination_ports": set(
                    finding["details"]["destination_ports"]
                ),
                "destination_ips": set(
                    finding["details"]["destination_ips"]
                ),
                "flow_ids": set(finding["flow_ids"]),
            }
            continue

        same_source = (
            source_ip == current_episode["source_ip"]
        )

        overlaps_episode = (
            window_start <= current_episode["end"]
        )

        if same_source and overlaps_episode:
            current_episode["end"] = max(
                current_episode["end"],
                window_end,
            )

            current_episode["destination_ports"].update(
                finding["details"]["destination_ports"]
            )

            current_episode["flow_ids"].update(
                finding["flow_ids"]
            )

            current_episode["destination_ips"].update(
                finding["details"]["destination_ips"]
            )

            if (
                finding["details"]["port_count"]
                > current_episode["max_port_count"]
            ):
                current_episode["max_port_count"] = (
                    finding["details"]["port_count"]
                )
                current_episode["max_port_timestamp"] = (
                    window_start
                )

        else:
            consolidated.append(current_episode)

            current_episode = {
                "source_ip": source_ip,
                "start": window_start,
                "end": window_end,
                "max_port_count": (
                    finding["details"]["port_count"]
                ),
                "max_port_timestamp": window_start,
                "destination_ports": set(
                    finding["details"]["destination_ports"]
                ),
                "destination_ips": set(
                    finding["details"]["destination_ips"]
                ),
                "flow_ids": set(finding["flow_ids"]),
            }

    consolidated.append(current_episode)

    return consolidated

def build_multi_port_findings(events):
    """Detect and consolidate multi-port activity episodes."""
    raw_findings = detect_multi_port_activity(events)

    episodes = consolidate_multi_port_findings(
        raw_findings
    )

    findings = []

    for index, episode in enumerate(episodes, start=1):
        findings.append(
            create_finding(
                rule_id="R02",
                rule_name="Multi-Port Activity",
                timestamp=episode["start"],
                source_ip=episode["source_ip"],
                description=(
                    f"Source contacted at least "
                    f"{MULTI_PORT_THRESHOLD} distinct "
                    f"destination ports within "
                    f"{MULTI_PORT_WINDOW_SECONDS} seconds."
                ),
                priority="Medium",
                flow_ids=sorted(
                    episode["flow_ids"]
                ),
                details={
                    "episode_id": f"R02-{index:04d}",
                    "episode_start": episode["start"],
                    "episode_end": episode["end"],
                    "max_port_count": (
                        episode["max_port_count"]
                    ),
                    "max_port_timestamp": (
                        episode["max_port_timestamp"]
                    ),
                    "destination_ports": sorted(
                        episode["destination_ports"]
                    ),
                    "destination_ips": sorted(
                        episode["destination_ips"]
                    ),
                    "total_flows": len(
                        episode["flow_ids"]
                    ),
                },
            )
        )

    return findings

# -----------------------------------------------------------
#                  Rule 3 functions zone
# -----------------------------------------------------------

def detect_repeated_failed_authentication(events):
    """Detect repeated failed FTP authentication attempts."""

    ftp_events = events[
        (events["event_type"] == "ftp")
        & events["src_ip"].notna()
    ].copy()

    if ftp_events.empty:
        return []

    failed_auth = []

    for _, event in ftp_events.iterrows():
        raw_event = event.get("raw")

        if not raw_event:
            continue

        try:
            import json

            raw_data = json.loads(raw_event)
        except (TypeError, json.JSONDecodeError):
            continue

        ftp_data = raw_data.get("ftp", {})
        replies = ftp_data.get("reply", [])

        if not isinstance(replies, list):
            replies = [replies]

        if not any(
            "Login incorrect" in str(reply)
            for reply in replies
        ):
            continue

        failed_auth.append(
            {
                "event_id": event["id"],
                "flow_id": event["flow_id"],
                "timestamp": event["ts"],
                "source_ip": event["src_ip"],
                "source_port": event["src_port"],
                "dest_ip": event["dest_ip"],
                "dest_port": event["dest_port"],
            }
        )

    if not failed_auth:
        return []

    failed_auth = pd.DataFrame(failed_auth)
    failed_auth = failed_auth.sort_values("timestamp")

    findings = []

    for source_ip, source_events in failed_auth.groupby("source_ip"):
        source_events = source_events.reset_index(drop=True)

        for _, event in source_events.iterrows():
            window_end = (
                event["timestamp"]
                + pd.Timedelta(
                    seconds=FAILED_AUTH_WINDOW_SECONDS
                )
            )

            window = source_events[
                (source_events["timestamp"] >= event["timestamp"])
                & (source_events["timestamp"] <= window_end)
            ]

            if len(window) >= FAILED_AUTH_THRESHOLD:
                findings.append(
                    create_finding(
                        rule_id="R03",
                        rule_name="Repeated Failed Authentication",
                        timestamp=event["timestamp"],
                        source_ip=source_ip,
                        description=(
                            f"Source generated {len(window)} failed FTP "
                            f"authentication attempts within "
                            f"{FAILED_AUTH_WINDOW_SECONDS} seconds."
                        ),
                        priority="Medium",
                        event_ids=window["event_id"].tolist(),
                        flow_ids=window["flow_id"].tolist(),
                        details={
                            "window_start": event["timestamp"],
                            "window_end": window["timestamp"].max(),
                            "failed_attempts": len(window),
                            "destination_ips": (
                                window["dest_ip"]
                                .dropna()
                                .unique()
                                .tolist()
                            ),
                            "destination_ports": (
                                window["dest_port"]
                                .dropna()
                                .unique()
                                .tolist()
                            ),
                        },
                    )
                )

                break

    return findings

# -----------------------------------------------------------
#                  Rule 4 functions zone
# -----------------------------------------------------------
def detect_repeated_protocol_anomalies(events):
    """Detect repeated protocol anomalies from external sources."""

    anomaly_events = events[
        (events["event_type"] == "anomaly")
        & events["src_ip"].notna()
        & events["dest_ip"].notna()
    ].copy()

    if anomaly_events.empty:
        return []

    # Only consider external source -> internal honeynet traffic.
    anomaly_events = anomaly_events[
        ~anomaly_events["src_ip"].apply(is_internal_ip)
        & anomaly_events["dest_ip"].apply(is_internal_ip)
    ].copy()

    if anomaly_events.empty:
        return []

    anomaly_events = anomaly_events.sort_values("ts")

    findings = []

    for source_ip, source_events in anomaly_events.groupby("src_ip"):
        source_events = source_events.reset_index(drop=True)

        for index, event in source_events.iterrows():
            window_end = (
                event["ts"]
                + pd.Timedelta(
                    seconds=PROTOCOL_ANOMALY_WINDOW_SECONDS
                )
            )

            window = source_events[
                (source_events["ts"] >= event["ts"])
                & (source_events["ts"] <= window_end)
            ]

            if len(window) >= PROTOCOL_ANOMALY_THRESHOLD:
                anomaly_types = []

                for raw_event in window["raw"].dropna():
                    try:
                        import json

                        raw_data = json.loads(raw_event)
                    except (TypeError, json.JSONDecodeError):
                        continue

                    anomaly_data = raw_data.get("anomaly", {})
                    anomaly_type = anomaly_data.get("event")

                    if anomaly_type:
                        anomaly_types.append(anomaly_type)

                findings.append(
                    create_finding(
                        rule_id="R04",
                        rule_name="Repeated External Protocol Anomaly",
                        timestamp=event["ts"],
                        source_ip=source_ip,
                        description=(
                            f"External source generated "
                            f"{len(window)} protocol anomalies "
                            f"within "
                            f"{PROTOCOL_ANOMALY_WINDOW_SECONDS} "
                            f"seconds."
                        ),
                        priority="Medium",
                        event_ids=window["id"].tolist(),
                        flow_ids=window["flow_id"].tolist(),
                        details={
                            "window_start": event["ts"],
                            "window_end": window["ts"].max(),
                            "anomaly_count": len(window),
                            "anomaly_types": sorted(
                                set(anomaly_types)
                            ),
                            "destination_ips": (
                                window["dest_ip"]
                                .dropna()
                                .unique()
                                .tolist()
                            ),
                            "destination_ports": (
                                window["dest_port"]
                                .dropna()
                                .unique()
                                .tolist()
                            ),
                        },
                    )
                )

    return findings

def consolidate_protocol_anomaly_findings(findings):
    """Combine overlapping protocol anomaly findings."""

    if not findings:
        return []

    consolidated = []

    findings = sorted(
        findings,
        key=lambda finding: (
            finding["source_ip"],
            finding["timestamp"],
        ),
    )

    current_episode = None

    for finding in findings:
        source_ip = finding["source_ip"]
        window_start = finding["timestamp"]
        window_end = finding["details"]["window_end"]

        if current_episode is None:
            current_episode = {
                "source_ip": source_ip,
                "start": window_start,
                "end": window_end,
                "max_anomaly_count": (
                    finding["details"]["anomaly_count"]
                ),
                "max_anomaly_timestamp": window_start,
                "anomaly_types": set(
                    finding["details"]["anomaly_types"]
                ),
                "destination_ips": set(
                    finding["details"]["destination_ips"]
                ),
                "destination_ports": set(
                    finding["details"]["destination_ports"]
                ),
                "event_ids": set(finding["event_ids"]),
                "flow_ids": set(finding["flow_ids"]),
            }
            continue

        same_source = (
            source_ip == current_episode["source_ip"]
        )

        overlaps_episode = (
            window_start <= current_episode["end"]
        )

        if same_source and overlaps_episode:
            current_episode["end"] = max(
                current_episode["end"],
                window_end,
            )

            current_episode["anomaly_types"].update(
                finding["details"]["anomaly_types"]
            )

            current_episode["destination_ips"].update(
                finding["details"]["destination_ips"]
            )

            current_episode["destination_ports"].update(
                finding["details"]["destination_ports"]
            )

            current_episode["event_ids"].update(
                finding["event_ids"]
            )

            current_episode["flow_ids"].update(
                finding["flow_ids"]
            )

            if (
                finding["details"]["anomaly_count"]
                > current_episode["max_anomaly_count"]
            ):
                current_episode["max_anomaly_count"] = (
                    finding["details"]["anomaly_count"]
                )

                current_episode["max_anomaly_timestamp"] = (
                    window_start
                )

        else:
            consolidated.append(current_episode)

            current_episode = {
                "source_ip": source_ip,
                "start": window_start,
                "end": window_end,
                "max_anomaly_count": (
                    finding["details"]["anomaly_count"]
                ),
                "max_anomaly_timestamp": window_start,
                "anomaly_types": set(
                    finding["details"]["anomaly_types"]
                ),
                "destination_ips": set(
                    finding["details"]["destination_ips"]
                ),
                "destination_ports": set(
                    finding["details"]["destination_ports"]
                ),
                "event_ids": set(finding["event_ids"]),
                "flow_ids": set(finding["flow_ids"]),
            }

    consolidated.append(current_episode)

    return consolidated

def build_protocol_anomaly_findings(events):
    """Detect and consolidate repeated protocol anomaly episodes."""

    raw_findings = detect_repeated_protocol_anomalies(events)

    episodes = consolidate_protocol_anomaly_findings(
        raw_findings
    )

    findings = []

    for index, episode in enumerate(episodes, start=1):
        findings.append(
            create_finding(
                rule_id="R04",
                rule_name="Repeated External Protocol Anomaly",
                timestamp=episode["start"],
                source_ip=episode["source_ip"],
                description=(
                    f"External source repeatedly generated "
                    f"protocol anomalies within "
                    f"{PROTOCOL_ANOMALY_WINDOW_SECONDS} "
                    f"seconds."
                ),
                priority="Medium",
                event_ids=sorted(
                    episode["event_ids"]
                ),
                flow_ids=sorted(
                    episode["flow_ids"]
                ),
                details={
                    "episode_id": f"R04-{index:04d}",
                    "episode_start": episode["start"],
                    "episode_end": episode["end"],
                    "max_anomaly_count": (
                        episode["max_anomaly_count"]
                    ),
                    "max_anomaly_timestamp": (
                        episode["max_anomaly_timestamp"]
                    ),
                    "anomaly_types": sorted(
                        episode["anomaly_types"]
                    ),
                    "destination_ips": sorted(
                        episode["destination_ips"]
                    ),
                    "destination_ports": sorted(
                        episode["destination_ports"]
                    ),
                    "total_events": len(
                        episode["event_ids"]
                    ),
                    "total_flows": len(
                        episode["flow_ids"]
                    ),
                },
            )
        )

    return findings

# To delete later:
if __name__ == "__main__":
    events = load_events()

    # Run all four rule-based detection rules
    r01 = build_high_connection_findings(events)
    r02 = build_multi_port_findings(events)
    r03 = detect_repeated_failed_authentication(events)
    r04 = build_protocol_anomaly_findings(events)

    all_findings = r01 + r02 + r03 + r04

    # Sort all findings chronologically
    all_findings = sorted(
        all_findings,
        key=lambda finding: finding["timestamp"],
    )

    print(f"Total events: {len(events):,}")
    print()
    print("Rule-based detection summary:")
    print(f"  R01 - High Connection Rate: {len(r01)}")
    print(f"  R02 - Multi-Port Activity: {len(r02)}")
    print(
        f"  R03 - Repeated Failed Authentication: "
        f"{len(r03)}"
    )
    print(
        f"  R04 - Repeated External Protocol Anomaly: "
        f"{len(r04)}"
    )
    print(f"  Total findings: {len(all_findings)}")
    print()
    print("=" * 100)
    print("ALL FINDINGS - CHRONOLOGICAL")
    print("=" * 100)

    for index, finding in enumerate(all_findings, start=1):
        details = finding["details"]

        print()
        print(
            f"[{index:02d}] "
            f"{finding['rule_id']} | "
            f"{finding['rule_name']}"
        )

        print(
            f"     Source: {finding['source_ip']} | "
            f"Time: {finding['timestamp']}"
        )

        print(
            f"     Events: "
            f"{len(finding['event_ids'])} | "
            f"Flows: "
            f"{len(finding['flow_ids'])}"
        )

        if finding["rule_id"] == "R01":
            print(
                f"     Max flows in window: "
                f"{details['max_flow_count']} | "
                f"Total episode flows: "
                f"{details['total_flows']}"
            )

        elif finding["rule_id"] == "R02":
            print(
                f"     Destination ports: "
                f"{details['destination_ports']} | "
                f"Total episode flows: "
                f"{details['total_flows']}"
            )

        elif finding["rule_id"] == "R03":
            print(
                f"     Failed attempts: "
                f"{details['failed_attempts']} | "
                f"Destination: "
                f"{details['destination_ips']}:"
                f"{details['destination_ports']}"
            )

        elif finding["rule_id"] == "R04":
            print(
                f"     Max anomalies in window: "
                f"{details['max_anomaly_count']} | "
                f"Anomaly types: "
                f"{details['anomaly_types']}"
            )