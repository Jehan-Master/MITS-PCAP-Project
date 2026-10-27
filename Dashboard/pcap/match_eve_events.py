import math
import ipaddress
from datetime import datetime, timezone

try:
    from .filter_packets import filter_packets
except ImportError:
    from filter_packets import filter_packets

DEFAULT_TOLERANCE_SECONDS = 0.5
DEFAULT_CANDIDATE_LIMIT = 1000


def parse_eve_timestamp(timestamp):
    """Convert an EVE timestamp to a UTC Unix timestamp."""
    if not isinstance(timestamp, str) or not timestamp:
        raise ValueError("EVE timestamp must be a non-empty string")

    try:
        parsed_timestamp = datetime.fromisoformat(
            timestamp.replace("Z", "+00:00")
        )
    except ValueError as error:
        raise ValueError("Invalid EVE timestamp format") from error

    if parsed_timestamp.tzinfo is None:
        raise ValueError("EVE timestamp must include a timezone")

    return parsed_timestamp.astimezone(timezone.utc).timestamp()

def normalize_ip_address(address):
    """Return a normalized IP address string."""
    if not isinstance(address, str):
        raise ValueError("IP address must be a string")

    try:
        return str(ipaddress.ip_address(address))
    except ValueError as error:
        raise ValueError("Invalid IP address") from error

def match_eve_event(
    event,
    tolerance_seconds=DEFAULT_TOLERANCE_SECONDS,
    candidate_limit=DEFAULT_CANDIDATE_LIMIT,
    pcap_filename=None,
):
    """Find PCAP packets that match an EVE event."""
    if not isinstance(event, dict):
        raise ValueError("event must be a dictionary")

    if (
        isinstance(tolerance_seconds, bool)
        or not isinstance(tolerance_seconds, (int, float))
        or not math.isfinite(tolerance_seconds)
        or tolerance_seconds < 0
    ):
        raise ValueError(
            "tolerance_seconds must be a finite, non-negative number"
        )

    if (
        isinstance(candidate_limit, bool)
        or not isinstance(candidate_limit, int)
        or candidate_limit < 1
    ):
        raise ValueError(
            "candidate_limit must be a positive integer"
        )

    event_type = event.get("event_type", "unknown")
    protocol = event.get("proto", "")

    # Statistics events do not represent individual network packets.
    if event_type == "stats":
        return {
            "status": "not_applicable",
            "event_type": event_type,
            "reason": (
                "Statistics events do not represent individual "
                "network packets and cannot be matched directly."
            ),
            "candidates": [],
        }

    # ICMP traffic does not use TCP or UDP ports.
    # This matcher currently requires a five-tuple.
    if (
        isinstance(protocol, str)
        and protocol.lower() in {"icmp", "icmpv6", "ipv6-icmp"}
        and (
            event.get("src_port") is None
            or event.get("dest_port") is None
        )
    ):
        return {
            "status": "not_applicable",
            "event_type": event_type,
            "reason": (
                "ICMP events without ports are not supported by "
                "the current five-tuple matching method."
            ),
            "candidates": [],
        }

    required_fields = (
        "timestamp",
        "src_ip",
        "src_port",
        "dest_ip",
        "dest_port",
        "proto",
    )

    missing_fields = [
        field for field in required_fields
        if field not in event or event[field] is None
    ]

    if missing_fields:
        return {
            "status": "invalid_event",
            "reason": (
                "Missing required fields: "
                + ", ".join(missing_fields)
            ),
            "candidates": [],
        }

    try:
        event_timestamp = parse_eve_timestamp(event["timestamp"])
    except ValueError as error:
        return {
            "status": "invalid_event",
            "reason": str(error),
            "candidates": [],
        }

    src_port = event["src_port"]
    dest_port = event["dest_port"]

    if (
        not isinstance(src_port, int)
        or isinstance(src_port, bool)
        or not 0 <= src_port <= 65535
        or not isinstance(dest_port, int)
        or isinstance(dest_port, bool)
        or not 0 <= dest_port <= 65535
    ):
        return {
            "status": "invalid_event",
            "reason": "Source and destination ports must be integers "
                      "between 0 and 65535",
            "candidates": [],
        }

    protocol = event["proto"]

    if not isinstance(protocol, str) or not protocol:
        return {
            "status": "invalid_event",
            "reason": "Protocol must be a non-empty string",
            "candidates": [],
        }

    try:
        src_ip = normalize_ip_address(event["src_ip"])
        dest_ip = normalize_ip_address(event["dest_ip"])
    except ValueError as error:
        return {
            "status": "invalid_event",
            "reason": str(error),
            "candidates": [],
        }

    
    # Select the appropriate time window for this event type.
    matching_start_epoch = event_timestamp - tolerance_seconds
    matching_end_epoch = event_timestamp + tolerance_seconds
    match_method = "five_tuple_and_timestamp"

    if event_type == "flow":
        flow = event.get("flow")

        if not isinstance(flow, dict):
            return {
                "status": "invalid_event",
                "reason": "Flow event is missing its flow object",
                "candidates": [],
            }

        try:
            flow_start = parse_eve_timestamp(flow.get("start"))
            flow_end = parse_eve_timestamp(flow.get("end"))
        except ValueError as error:
            return {
                "status": "invalid_event",
                "reason": f"Invalid flow start or end timestamp: {error}",
                "candidates": [],
            }

        if flow_start > flow_end:
            return {
                "status": "invalid_event",
                "reason": "Flow start timestamp must not exceed flow end",
                "candidates": [],
            }

        matching_start_epoch = flow_start
        matching_end_epoch = flow_end
        match_method = "five_tuple_and_flow_interval"

    
    packets = filter_packets(
        pcap_filename=pcap_filename,
        src_ip=src_ip,
        src_port=src_port,
        dest_ip=dest_ip,
        dest_port=dest_port,
        protocol=protocol.lower(),
        start_epoch=matching_start_epoch,
        end_epoch=matching_end_epoch,
        limit=candidate_limit,
    )

    candidates = []

    event_type = event.get("event_type", "")
    app_protocol = event.get("app_proto", "")

    anomaly = event.get("anomaly")
    anomaly_app_protocol = (
        anomaly.get("app_proto", "")
        if isinstance(anomaly, dict)
        else ""
    )

    expected_app_protocols = {
        value.lower()
        for value in (
            event_type,
            app_protocol,
            anomaly_app_protocol,
        )
        if isinstance(value, str) and value
    }

    for packet in packets:
        time_difference = (
            packet["timestamp_epoch"] - event_timestamp
        )

        packet_protocols = {
            protocol.lower()
            for protocol in packet["protocols"].split(":")
            if protocol
        }

        protocol_context_match = bool(
            expected_app_protocols & packet_protocols
        )

        candidates.append({
            **packet,
            "time_difference_seconds": time_difference,
            "absolute_time_difference_seconds": abs(
                time_difference
            ),
            "protocol_context_match": protocol_context_match,
            "match_method": match_method,
        })

    
    if match_method == "five_tuple_and_flow_interval":
        candidates.sort(
            key=lambda candidate: (
                candidate["timestamp_epoch"],
                candidate["frame_number"],
            )
        )
    else:
        candidates.sort(
            key=lambda candidate: (
                candidate["absolute_time_difference_seconds"],
                not candidate["protocol_context_match"],
                candidate["pcap_filename"],
                candidate["frame_number"],
            )
        )

    if not candidates:
        status = "unmatched"
    elif len(candidates) == 1:
        status = "matched"
    else:
        status = "ambiguous"

    return {
        "status": status,
        "event_type": event.get("event_type", "unknown"),
        "flow_id": event.get("flow_id"),
        "tolerance_seconds": tolerance_seconds,
        "candidate_count": len(candidates),
        "candidate_limit_reached": (
            len(packets) == candidate_limit
        ),
        "candidates": candidates,
    }