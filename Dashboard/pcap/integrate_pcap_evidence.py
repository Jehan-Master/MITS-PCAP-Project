
"""Add PCAP matching evidence to EVE-JSONL events."""

import argparse
import json
import os
import sys
import tempfile
from collections import Counter
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
PCAP_FOLDER = Path(__file__).resolve().parent

if str(PCAP_FOLDER) not in sys.path:
    sys.path.insert(0, str(PCAP_FOLDER))

from match_eve_events import match_eve_event  # noqa: E402


INTERPRETATION_NOTE = (
    "PCAP matches are supporting evidence only and do not, by themselves, "
    "establish that an event is malicious."
)


def enrich_event(event, pcap_filename=None):
    """Return an EVE event with its PCAP matching evidence."""
    if not isinstance(event, dict):
        enriched_event = {
            "original_event": event,
            "pcap_evidence": {
                "status": "invalid_event",
                "reason": "The JSON value must be an EVE event object.",
                "candidate_count": 0,
                "candidate_limit_reached": False,
                "candidates": [],
                "interpretation_note": INTERPRETATION_NOTE,
            },
        }
        return enriched_event, "invalid_event"

    # Keep the original event fields and add the matching results.
    enriched_event = dict(event)
    result = match_eve_event(event, pcap_filename=pcap_filename)

    evidence = dict(result)
    evidence.setdefault("candidate_count", len(evidence.get("candidates", [])))
    evidence.setdefault("candidate_limit_reached", False)
    evidence["interpretation_note"] = INTERPRETATION_NOTE

    enriched_event["pcap_evidence"] = evidence
    return enriched_event, evidence["status"]


def integrate_eve_file(input_path, output_path, pcap_filename=None):
    """Stream an EVE JSONL file into a separate enriched JSONL file."""
    input_path = Path(input_path).resolve()
    output_path = Path(output_path).resolve()

    if not input_path.is_file():
        raise FileNotFoundError(f"Input file not found: {input_path}")

    if input_path == output_path:
        raise ValueError("Input and output files must be different.")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    counts = Counter()
    blank_lines = 0
    processed_events = 0

    # Write to a temporary file so an incomplete run does not replace
    # an existing final output file.
    temp_path = None

    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            dir=output_path.parent,
            prefix=f"{output_path.name}.",
            suffix=".tmp",
            delete=False,
        ) as temp_file:
            temp_path = Path(temp_file.name)

            with input_path.open("r", encoding="utf-8") as input_file:
                for line_number, line in enumerate(input_file, start=1):
                    if not line.strip():
                        blank_lines += 1
                        continue

                    try:
                        event = json.loads(line)
                    except json.JSONDecodeError as exc:
                        raise ValueError(
                            f"Invalid JSON on line {line_number}: {exc}"
                        ) from exc

                    try:
                        enriched_event, status = enrich_event(event, pcap_filename=pcap_filename)
                    except Exception as exc:
                        raise RuntimeError(
                            "PCAP matching failed on input line "
                            f"{line_number}. No final output was published."
                        ) from exc

                    json.dump(
                        enriched_event,
                        temp_file,
                        ensure_ascii=False,
                        separators=(",", ":"),
                    )
                    temp_file.write("\n")

                    counts[status] += 1
                    processed_events += 1

        os.replace(temp_path, output_path)
        temp_path = None

    finally:
        if temp_path is not None and temp_path.exists():
            temp_path.unlink()

    print(f"Input file:  {input_path}")
    print(f"Output file: {output_path}")
    print(f"Events processed: {processed_events}")
    print(f"Blank lines skipped: {blank_lines}")
    print("Matching status counts:")

    for status in ("matched", "ambiguous", "unmatched", "not_applicable", "invalid_event"):
        print(f"  {status}: {counts[status]}")

    return counts


def main():
    """Parse command-line arguments and run the integration."""
    parser = argparse.ArgumentParser(
        description="Enrich EVE JSONL events with PCAP matching evidence."
    )
    parser.add_argument(
        "input_file",
        type=Path,
        help="Path to the source EVE JSONL file.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help=(
            "Path for the enriched JSONL output. If omitted, the output "
            "is written to data/enriched/<input_stem>_with_pcap.jsonl."
        ),
    )
    parser.add_argument(
        "--pcap",
        type=str,
        default=None,
        help=(
            "Restrict matching to this PCAP filename, "
            "for example 2026-06-20.pcapng."
        ),
    )
    args = parser.parse_args()

    input_path = args.input_file
    if not input_path.is_absolute():
        input_path = PROJECT_ROOT / input_path

    if args.output is None:
        output_path = (
            PROJECT_ROOT
            / "data"
            / "enriched"
            / f"{input_path.stem}_with_pcap.jsonl"
        )
    else:
        output_path = args.output
        if not output_path.is_absolute():
            output_path = PROJECT_ROOT / output_path

    integrate_eve_file(input_path, output_path, pcap_filename=args.pcap)


if __name__ == "__main__":
    main()
