from itertools import combinations

import pandas as pd

from analysis.detection import (
    build_high_connection_findings,
    build_multi_port_findings,
    detect_repeated_failed_authentication,
    build_protocol_anomaly_findings,
    load_events,
)

TIME_WINDOW_SECONDS = 5 * 60


def get_finding_id(finding, index):
    """Return a stable ID for a finding."""
    return f"{finding['rule_id']}-{index:04d}"


def get_destinations(finding):
    """Return destination IPs associated with a finding."""
    details = finding.get("details", {})

    destinations = details.get("destination_ips", [])

    if isinstance(destinations, str):
        destinations = [destinations]

    return set(destinations)


def get_ports(finding):
    """Return destination ports associated with a finding."""
    details = finding.get("details", {})

    ports = details.get("destination_ports", [])

    if isinstance(ports, (int, float)):
        ports = [ports]

    return set(ports)


def get_flow_ids(finding):
    """Return flow IDs associated with a finding."""
    return set(finding.get("flow_ids", []))

def get_session_ids(finding):
    """Return session IDs associated with a finding."""
    return set(finding.get("session_ids", []))

def compare_findings(finding_a, finding_b):
    """
    Compare two findings and return correlation evidence.
    """

    source_a = finding_a.get("source_ip")
    source_b = finding_b.get("source_ip")

    same_source = (
        source_a is not None
        and source_a == source_b
    )

    timestamp_a = pd.Timestamp(
        finding_a["timestamp"]
    )
    timestamp_b = pd.Timestamp(
        finding_b["timestamp"]
    )

    time_difference = abs(
        (timestamp_a - timestamp_b).total_seconds()
    )

    within_time_window = (
        time_difference <= TIME_WINDOW_SECONDS
    )

    destinations_a = get_destinations(finding_a)
    destinations_b = get_destinations(finding_b)

    same_destination = bool(
        destinations_a & destinations_b
    )

    ports_a = get_ports(finding_a)
    ports_b = get_ports(finding_b)

    overlapping_ports = bool(
        ports_a & ports_b
    )

    flows_a = get_flow_ids(finding_a)
    flows_b = get_flow_ids(finding_b)

    shared_flow = bool(
        flows_a & flows_b
    )
    
    sessions_a = get_session_ids(finding_a)
    sessions_b = get_session_ids(finding_b)

    shared_sessions = sessions_a & sessions_b

    different_rules = (
        finding_a["rule_id"] != finding_b["rule_id"]
    )

    reasons = []

    if shared_flow:
        reasons.append("Shared flow")

    if shared_sessions:
        for session_id in sorted(shared_sessions):
            reasons.append(
                f"Shared session: {session_id}"
            )

    if same_source:
        reasons.append("Same source IP")

    if within_time_window:
        reasons.append("Within 5-minute window")

    if same_destination:
        reasons.append("Same destination IP")

    if overlapping_ports:
        reasons.append("Overlapping destination port")

    if different_rules:
        reasons.append("Different detection rules")

    # Strong relationship
    if shared_flow:
        strength = "Strong"

    elif (
        same_source
        and same_destination
        and within_time_window
    ):
        strength = "Strong"

    # Moderate relationship
    elif (
        same_source
        and within_time_window
        and (
            same_destination
            or overlapping_ports
            or different_rules
        )
    ):
        strength = "Moderate"

    else:
        strength = None

    return {
        "correlated": strength is not None,
        "strength": strength,
        "time_difference_seconds": time_difference,
        "shared_sessions": sorted(shared_sessions),
        "reasons": reasons,
    }

# --------------------------------------------------------
#                Build candidate cases
# --------------------------------------------------------

def build_candidate_cases(findings):
    """
    Group correlated findings into candidate cases.

    Findings are expected to already contain a finding_id.
    The pipeline assigns these IDs once before correlation.
    """

    finding_records = []

    for finding in findings:
        record = finding.copy()

        if "finding_id" not in record:
            raise ValueError(
                "Finding is missing required finding_id."
            )

        finding_records.append(record)

    # Build a graph of correlated findings
    connections = {
        record["finding_id"]: set()
        for record in finding_records
    }

    relationships = []

    for finding_a, finding_b in combinations(
        finding_records,
        2,
    ):
        comparison = compare_findings(
            finding_a,
            finding_b,
        )

        if comparison["correlated"]:
            id_a = finding_a["finding_id"]
            id_b = finding_b["finding_id"]

            connections[id_a].add(id_b)
            connections[id_b].add(id_a)

            relationships.append(
                {
                    "finding_a": id_a,
                    "finding_b": id_b,
                    **comparison,
                }
            )

    # Find connected components
    visited = set()
    cases = []

    for finding in finding_records:
        finding_id = finding["finding_id"]

        if finding_id in visited:
            continue

        stack = [finding_id]
        component = []

        while stack:
            current = stack.pop()

            if current in visited:
                continue

            visited.add(current)
            component.append(current)

            for neighbour in connections[current]:
                if neighbour not in visited:
                    stack.append(neighbour)

        cases.append(component)

    # Build final case objects
    finding_lookup = {
        finding["finding_id"]: finding
        for finding in finding_records
    }

    candidate_cases = []

    for case_index, component in enumerate(
        cases,
        start=1,
    ):
        case_findings = [
            finding_lookup[finding_id]
            for finding_id in component
        ]

        timestamps = [
            pd.Timestamp(finding["timestamp"])
            for finding in case_findings
        ]

        source_ips = {
            finding["source_ip"]
            for finding in case_findings
            if finding.get("source_ip")
        }

        destination_ips = set()

        for finding in case_findings:
            destination_ips.update(
                get_destinations(finding)
            )

        rule_ids = sorted(
            {
                finding["rule_id"]
                for finding in case_findings
            }
        )

        case_relationships = [
            relationship
            for relationship in relationships
            if (
                relationship["finding_a"]
                in component
                and relationship["finding_b"]
                in component
            )
        ]

        reasons = sorted(
            {
                reason
                for relationship in case_relationships
                for reason in relationship["reasons"]
            }
        )

        strengths = [
            relationship["strength"]
            for relationship in case_relationships
        ]

        if "Strong" in strengths:
            case_strength = "Strong"
        elif "Moderate" in strengths:
            case_strength = "Moderate"
        else:
            case_strength = "Single"

        candidate_cases.append(
            {
                "case_id": (
                    f"CASE-{case_index:04d}"
                ),
                "first_seen": min(timestamps),
                "last_seen": max(timestamps),
                "source_ips": sorted(source_ips),
                "destination_ips": sorted(
                    destination_ips
                ),
                "finding_ids": component,
                "rule_ids": rule_ids,
                "finding_count": len(component),
                "correlation_strength": case_strength,
                "correlation_reasons": reasons,
            }
        )

        candidate_cases.sort(
            key=lambda case: case["first_seen"]
        )
        
        for index, case in enumerate(
            candidate_cases,
            start=1,
        ):
            case["case_id"] = f"CASE-{index:04d}"

    return candidate_cases

# --------------------------------------------------------
#                      Test block
# --------------------------------------------------------

if __name__ == "__main__":
    events = load_events()

    r01 = build_high_connection_findings(events)
    r02 = build_multi_port_findings(events)
    r03 = detect_repeated_failed_authentication(events)
    r04 = build_protocol_anomaly_findings(events)

    findings = r01 + r02 + r03 + r04

    cases = build_candidate_cases(findings)

    # --------------------------------------------------------
    # Sort cases chronologically
    # --------------------------------------------------------

    cases.sort(
        key=lambda case: case["first_seen"]
    )

    for index, case in enumerate(
        cases,
        start=1,
    ):
        case["case_id"] = f"CASE-{index:04d}"

    # --------------------------------------------------------
    # Build finding -> case lookup
    # --------------------------------------------------------

    finding_to_cases = {}

    for case in cases:
        for finding_id in case["finding_ids"]:
            finding_to_cases.setdefault(
                finding_id,
                []
            ).append(case["case_id"])

    # --------------------------------------------------------
    # Validation 1: every finding assigned exactly once
    # --------------------------------------------------------

    expected_finding_count = len(findings)
    assigned_finding_count = sum(
        len(case["finding_ids"])
        for case in cases
    )

    duplicate_findings = {
        finding_id: case_ids
        for finding_id, case_ids
        in finding_to_cases.items()
        if len(case_ids) > 1
    }

    missing_findings = []

    all_finding_ids = set()

    for index, finding in enumerate(
        findings,
        start=1,
    ):
        all_finding_ids.add(
            get_finding_id(
                finding,
                index,
            )
        )

    assigned_finding_ids = set(
        finding_to_cases.keys()
    )

    missing_findings = sorted(
        all_finding_ids - assigned_finding_ids
    )

    assignment_pass = (
        expected_finding_count
        == assigned_finding_count
        and not duplicate_findings
        and not missing_findings
    )

    # --------------------------------------------------------
    # Validation 2: expected multi-finding cases
    # --------------------------------------------------------

    def find_case_with_findings(
        required_finding_ids
    ):
        required = set(required_finding_ids)

        for case in cases:
            case_findings = set(
                case["finding_ids"]
            )

            if required.issubset(case_findings):
                return case

        return None

    expected_relationships = [
        (
            "43.98.162.27 R03 + R04",
            ["R03-0028", "R04-0033"],
        ),
        (
            "121.229.43.157 R01 + R02 + R04",
            ["R01-0005", "R02-0021", "R04-0029"],
        ),
        (
            "182.244.11.140 R01 + R02 at 05:43",
            ["R01-0011", "R02-0022"],
        ),
        (
            "182.244.11.140 R01 + R02 at 08:52",
            ["R01-0012", "R02-0023"],
        ),
        (
            "207.175.14.104 R04 + R01",
            ["R04-0031", "R01-0014"],
        ),
        (
            "34.38.5.183 R04 + R01",
            ["R04-0032", "R01-0015"],
        ),
    ]

    relationship_results = []

    for name, required_ids in expected_relationships:
        case = find_case_with_findings(
            required_ids
        )

        relationship_results.append(
            (
                name,
                case is not None,
                case["case_id"] if case else None,
            )
        )

    relationships_pass = all(
        result[1]
        for result in relationship_results
    )

    # --------------------------------------------------------
    # Validation 3: known separate activities
    # --------------------------------------------------------

    separate_groups = [
        (
            "31.129.55.212 separate R02 findings",
            [
                "R02-0024",
                "R02-0025",
                "R02-0026",
            ],
        ),
        (
            "176.65.132.17 separate R01 findings",
            [
                "R01-0008",
                "R01-0009",
                "R01-0010",
            ],
        ),
    ]

    separation_results = []

    for name, finding_ids in separate_groups:
        case_ids = []

        for finding_id in finding_ids:
            case_ids.append(
                finding_to_cases.get(
                    finding_id,
                    []
                )
            )

        flattened_case_ids = [
            case_id
            for ids in case_ids
            for case_id in ids
        ]

        separate = (
            len(flattened_case_ids)
            == len(set(flattened_case_ids))
        )

        separation_results.append(
            (
                name,
                separate,
                flattened_case_ids,
            )
        )

    separation_pass = all(
        result[1]
        for result in separation_results
    )

    # --------------------------------------------------------
    # Print summary
    # --------------------------------------------------------

    print()
    print("=" * 100)
    print("CORRELATION VALIDATION SUMMARY")
    print("=" * 100)

    print()
    print(
        f"Total findings: {expected_finding_count}"
    )

    print(
        f"Candidate cases: {len(cases)}"
    )

    print(
        f"Findings assigned to cases: "
        f"{assigned_finding_count}"
    )

    print()

    print(
        "Finding assignment test: "
        f"{'PASS' if assignment_pass else 'FAIL'}"
    )

    if duplicate_findings:
        print(
            "Duplicate findings:"
        )

        for finding_id, case_ids in (
            duplicate_findings.items()
        ):
            print(
                f"  {finding_id}: {case_ids}"
            )

    if missing_findings:
        print(
            "Missing findings:"
        )

        for finding_id in missing_findings:
            print(
                f"  {finding_id}"
            )

    print()
    print(
        "Expected relationship test: "
        f"{'PASS' if relationships_pass else 'FAIL'}"
    )

    for (
        name,
        passed,
        case_id,
    ) in relationship_results:
        print(
            f"  {'PASS' if passed else 'FAIL'} "
            f"| {name}"
            + (
                f" | {case_id}"
                if case_id
                else ""
            )
        )

    print()
    print(
        "Separate activity test: "
        f"{'PASS' if separation_pass else 'FAIL'}"
    )

    for (
        name,
        passed,
        case_ids,
    ) in separation_results:
        print(
            f"  {'PASS' if passed else 'FAIL'} "
            f"| {name} | {case_ids}"
        )

    overall_pass = (
        assignment_pass
        and relationships_pass
        and separation_pass
    )

    print()
    print("=" * 100)
    print(
        "OVERALL VALIDATION: "
        f"{'PASS' if overall_pass else 'FAIL'}"
    )
    print("=" * 100)

    # --------------------------------------------------------
    # Evaluation statistics
    # --------------------------------------------------------

    print()
    print("=" * 100)
    print("CASE EVALUATION STATISTICS")
    print("=" * 100)

    # Finding count distribution
    finding_count_distribution = {}

    for case in cases:
        count = case["finding_count"]

        finding_count_distribution[count] = (
            finding_count_distribution.get(count, 0)
            + 1
        )

    print()
    print("Findings per case:")

    for count in sorted(
        finding_count_distribution
    ):
        print(
            f"  {count} finding(s): "
            f"{finding_count_distribution[count]} case(s)"
        )

    # Correlation strength distribution
    strength_distribution = {}

    for case in cases:
        strength = case[
            "correlation_strength"
        ]

        strength_distribution[strength] = (
            strength_distribution.get(strength, 0)
            + 1
        )

    print()
    print("Correlation strength:")

    for strength in [
        "Strong",
        "Moderate",
        "Single",
    ]:
        print(
            f"  {strength}: "
            f"{strength_distribution.get(strength, 0)}"
        )

    # Correlation reason distribution
    reason_distribution = {}

    for case in cases:
        for reason in case[
            "correlation_reasons"
        ]:
            reason_distribution[reason] = (
                reason_distribution.get(reason, 0)
                + 1
            )

    print()
    print("Correlation reasons:")

    for reason, count in sorted(
        reason_distribution.items()
    ):
        print(
            f"  {reason}: {count}"
        )

    # Multi-finding cases
    multi_finding_cases = [
        case
        for case in cases
        if case["finding_count"] > 1
    ]

    print()
    print(
        "Multi-finding cases:"
    )

    for case in multi_finding_cases:
        print(
            f"  {case['case_id']} | "
            f"{case['finding_count']} findings | "
            f"{case['correlation_strength']} | "
            f"{case['source_ips']}"
        )

    # --------------------------------------------------------
    # Print candidate cases
    # --------------------------------------------------------

    print()
    print("=" * 100)
    print("CANDIDATE CASES")
    print("=" * 100)

    for case in cases:
        print()
        print(
            f"{case['case_id']} | "
            f"{case['correlation_strength']}"
        )

        print(
            f"  Time: "
            f"{case['first_seen']} -> "
            f"{case['last_seen']}"
        )

        print(
            f"  Sources: "
            f"{case['source_ips']}"
        )

        print(
            f"  Destinations: "
            f"{case['destination_ips']}"
        )

        print(
            f"  Findings: "
            f"{case['finding_ids']}"
        )

        print(
            f"  Rules: "
            f"{case['rule_ids']}"
        )

        print(
            f"  Correlation reasons: "
            f"{case['correlation_reasons']}"
        )