import csv
import json
from datetime import datetime
from pathlib import Path

HTTP_CSV = Path("data/pcap_metadata/http_evidence.csv")
EVE_JSONL = Path("input/eve_2026-06-20.json")


def load_http_records(csv_path):
    """Load extracted HTTP records from a pipe-delimited CSV."""
    with csv_path.open("r", encoding="utf-8-sig", newline="") as file:
        return list(csv.DictReader(file, delimiter="|"))


def find_eve_event(jsonl_path, line_number):
    """Return one EVE event using its one-based JSONL line number."""
    with jsonl_path.open("r", encoding="utf-8") as file:
        for current_line, line in enumerate(file, start=1):
            if current_line == line_number:
                return json.loads(line)

    raise ValueError(f"EVE JSONL line {line_number} does not exist")


def parse_eve_timestamp(value):
    """Convert an EVE timestamp to Unix seconds."""
    if not value:
        return None

    normalized = value
    if normalized.endswith("+0000"):
        normalized = normalized[:-5] + "+00:00"

    return datetime.fromisoformat(normalized).timestamp()


def as_int(value):
    """Convert a non-empty value to an integer."""
    if value in (None, ""):
        return None
    return int(value)


def event_http_details(event):
    """Extract HTTP attributes available in an EVE event."""
    http = event.get("http", {})
    fileinfo = event.get("fileinfo", {})

    if not isinstance(http, dict):
        http = {}
    if not isinstance(fileinfo, dict):
        fileinfo = {}

    method = http.get("http_method")
    uri = http.get("url") or fileinfo.get("filename")
    status = http.get("status")
    length = http.get("length") or fileinfo.get("size")

    return {
        "method": method,
        "uri": uri,
        "status": as_int(status),
        "length": as_int(length),
    }



def associate_http_event(event, records):
    """Associate an EVE HTTP event with compatible HTTP transactions."""
    event_type = event.get("event_type", "")
    if event_type not in {"http", "fileinfo"}:
        return {
            "status": "not_applicable",
            "reason": "Only HTTP and fileinfo events are supported.",
            "candidates": [],
        }

    try:
        src_port = int(event["src_port"])
        dest_port = int(event["dest_port"])
    except (KeyError, TypeError, ValueError):
        return {
            "status": "invalid_event",
            "reason": "Missing or invalid event ports.",
            "candidates": [],
        }

    src_ip = event.get("src_ip")
    dest_ip = event.get("dest_ip")
    details = event_http_details(event)

    matching_records = []

    for record in records:
        record_src_port = as_int(record.get("src_port"))
        record_dest_port = as_int(record.get("dest_port"))

        forward = (
            record.get("src_ip") == src_ip
            and record_src_port == src_port
            and record.get("dest_ip") == dest_ip
            and record_dest_port == dest_port
        )
        reverse = (
            record.get("src_ip") == dest_ip
            and record_src_port == dest_port
            and record.get("dest_ip") == src_ip
            and record_dest_port == src_port
        )

        if not (forward or reverse):
            continue

        method = record.get("http_method") or None
        uri = record.get("http_uri") or None
        status_code = as_int(record.get("http_status"))
        length = as_int(record.get("http_content_length"))

        comparisons = {}
        for name, expected, observed in (
            ("method", details["method"], method),
            ("uri", details["uri"], uri),
            ("status", details["status"], status_code),
            ("length", details["length"], length),
        ):
            if expected is not None and observed is not None:
                comparisons[name] = {
                    "expected": expected,
                    "observed": observed,
                    "matches": expected == observed,
                }

        if any(
            not comparison["matches"]
            for comparison in comparisons.values()
        ):
            continue

        matching_records.append({
            "pcap_filename": record.get("pcap_filename"),
            "frame_number": as_int(record.get("frame_number")),
            "timestamp_epoch": float(record["timestamp_epoch"]),
            "direction": "forward" if forward else "reverse",
            "http_method": method,
            "http_uri": uri,
            "http_status": status_code,
            "http_content_length": length,
            "attribute_comparisons": comparisons,
        })

    # Keep request and response records separate until compatible pairs
    # have been identified within the same capture.
    requests = [
        record for record in matching_records
        if record["http_method"] is not None
    ]
    responses = [
        record for record in matching_records
        if record["http_status"] is not None
    ]

    transactions = []
    paired_request_frames = set()
    paired_response_frames = set()

    for request in requests:
        for response in responses:
            if request["pcap_filename"] != response["pcap_filename"]:
                continue

            if request["direction"] == response["direction"]:
                continue

            if (
                request["http_uri"] is not None
                and response["http_uri"] is not None
                and request["http_uri"] != response["http_uri"]
            ):
                continue

            if response["timestamp_epoch"] < request["timestamp_epoch"]:
                continue

            transactions.append({
                "pcap_filename": request["pcap_filename"],
                "request_frame_number": request["frame_number"],
                "response_frame_number": response["frame_number"],
                "request_timestamp_epoch": request["timestamp_epoch"],
                "response_timestamp_epoch": response["timestamp_epoch"],
                "request_method": request["http_method"],
                "request_uri": request["http_uri"],
                "response_uri": response["http_uri"],
                "response_status": response["http_status"],
                "response_content_length": (
                    response["http_content_length"]
                ),
                "request_attribute_comparisons": (
                    request["attribute_comparisons"]
                ),
                "response_attribute_comparisons": (
                    response["attribute_comparisons"]
                ),
                "response_to_event_difference_seconds": (
                    response["timestamp_epoch"]
                    - float(event.get("_unused_timestamp", 0))
                ) if False else None,
            })
            paired_request_frames.add((
                request["pcap_filename"],
                request["frame_number"],
            ))
            paired_response_frames.add((
                response["pcap_filename"],
                response["frame_number"],
            ))

    # An unmatched frame is retained as an incomplete transaction candidate.
    for record in matching_records:
        frame_key = (
            record["pcap_filename"],
            record["frame_number"],
        )

        if record["http_method"] is not None:
            if frame_key in paired_request_frames:
                continue
            kind = "request_only"
        elif record["http_status"] is not None:
            if frame_key in paired_response_frames:
                continue
            kind = "response_only"
        else:
            kind = "http_frame"

        transactions.append({
            "pcap_filename": record["pcap_filename"],
            "kind": kind,
            "frame_number": record["frame_number"],
            "timestamp_epoch": record["timestamp_epoch"],
            "http_method": record["http_method"],
            "http_uri": record["http_uri"],
            "http_status": record["http_status"],
            "http_content_length": record["http_content_length"],
            "attribute_comparisons": record["attribute_comparisons"],
        })

    if not transactions:
        status = "unmatched"
    elif len(transactions) == 1:
        status = "associated"
    else:
        status = "ambiguous"

    return {
        "status": status,
        "event_type": event_type,
        "flow_id": event.get("flow_id"),
        "method": "endpoint_tuple_and_http_attributes",
        "candidate_count": len(transactions),
        "candidates": transactions,
        "interpretation_note": (
            "A transaction association is supporting evidence, not proof "
            "of a unique event-to-transaction relationship. Incomplete "
            "transactions and multiple compatible pairs remain explicit."
        ),
    }

if __name__ == "__main__":
    http_records = load_http_records(HTTP_CSV)

    # Test the known fileinfo event on line 825.
    event = find_eve_event(EVE_JSONL, 825)
    result = associate_http_event(event, http_records)

    print(json.dumps(result, indent=2))
