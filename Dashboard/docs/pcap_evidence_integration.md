# PCAP-09 — Integrate PCAP Evidence into Analysis Data

## 1. Objective

The objective of PCAP-09 is to enrich Suricata EVE-JSON events with supporting evidence from packet capture (PCAP) metadata. This allows analysts to investigate EVE events and identify potentially related packets without manually searching the original packet captures.

The integration uses the SQLite PCAP metadata index and the event-matching functionality implemented in the PCAP processing module.

## 2. Implementation

The integration is implemented in `pcap/integrate_pcap_evidence.py`, which uses the matching functionality in `pcap/match_eve_events.py`.

The integration process:

1. Reads the input EVE-JSON file as JSON Lines (JSONL).
2. Processes each non-empty line as an individual event.
3. Attempts to match eligible events against indexed PCAP metadata.
4. Attaches a `pcap_evidence` object to each event.
5. Writes the enriched events to a separate JSONL output file.
6. Reports the number of processed events and the count for each matching status.

The input event information is preserved, and the additional evidence is stored separately under `pcap_evidence`.

The integration supports an optional `--pcap` argument to restrict matching to a specific PCAP file. This is important when processing daily EVE data alongside PCAP captures from multiple dates.

### 2.1 Matching approach

The current matching method uses the event's network endpoints, protocol, and timestamp to identify candidate packets. Matching uses a default timestamp tolerance of ±0.5 seconds.

Candidates include information such as:

- PCAP filename and frame number.
- Packet timestamp.
- Source and destination IP addresses and ports.
- Protocol information.
- Timestamp difference between the event and packet.
- Protocol-context match indicator.
- Matching method.

The matcher preserves multiple candidates when it cannot identify a unique packet. This avoids presenting an uncertain association as a definitive match.

### 2.2 Matching statuses

| Status | Meaning |
|---|---|
| `matched` | Exactly one candidate packet was identified. |
| `ambiguous` | Multiple candidate packets were identified. |
| `unmatched` | No candidate packet met the matching criteria. |
| `not_applicable` | The event cannot be matched using the current method, such as a statistics event or an ICMP event without ports. |
| `invalid_event` | The event lacks required information or is otherwise unsuitable for matching. |

A matching result provides supporting evidence for investigation. It does not, by itself, establish that an event is malicious or that a candidate packet definitively represents the event.

## 3. Validation

### 3.1 Integration test

A test fixture containing four events was processed successfully.

| Result | Count |
|---|---:|
| Matched | 1 |
| Ambiguous | 1 |
| Unmatched | 1 |
| Not applicable | 0 |
| Invalid event | 1 |
| **Total** | **4** |

This test confirmed that the integration could process events representing different matching outcomes and report their statuses.

A malformed-JSON test also confirmed that an invalid input line produces a line-specific error and that an incomplete output is not published as the final output.

### 3.2 Full sample integration

The integration was executed against the sample file `input/eve_2026-06-20.json`, with matching restricted to `2026-06-20.pcapng`.

Output:

`data/enriched/eve_2026-06-20_with_pcap.jsonl`

Results:

| Result | Events | Percentage |
|---|---:|---:|
| Matched | 241 | 0.43% |
| Ambiguous | 20,075 | 35.64% |
| Unmatched | 25,144 | 44.63% |
| Not applicable | 10,871 | 19.30% |
| Invalid event | 0 | 0.00% |
| **Total** | **56,331** | **100%** |

The full integration completed without reporting invalid events. Statistics events and ICMP events without ports were classified as not applicable under the current matching method.

### 3.3 Output integrity and PCAP scope

The generated JSONL file was read back and checked.

The validation confirmed that:

- All 56,331 events could be read.
- Every event contained a `pcap_evidence` object.
- Every evidence object contained an interpretation note.
- The matching-status counts agreed with the integration summary.
- 20,316 events contained at least one candidate.
- A total of 147,836 candidate records were inspected.
- All 147,836 candidates referenced `2026-06-20.pcapng`.
- No candidate was missing its PCAP filename.
- No candidate referenced an unexpected PCAP file.

These checks support the conclusion that the output was successfully enriched and that the candidate records were scoped to the intended daily PCAP file.

## 4. Limitations

The implementation has several limitations that must be considered when interpreting its results.

1. **Ambiguous candidates:** Multiple packets can share the same network endpoints and timestamp. The matcher may therefore be unable to identify one unique packet.
2. **Unmatched events:** A lack of candidates does not necessarily mean that no related packet exists. The event may not be supported by the current matching method or may fall outside the configured timestamp tolerance.
3. **Protocol coverage:** The current five-tuple approach requires transport ports. Events such as ICMPv6 Router Solicitation messages are classified as not applicable rather than matched.
4. **Matching accuracy:** The integration tests establish that the pipeline and output behave as expected for the tested cases. They do not establish the overall accuracy of matching across the full dataset.
5. **Dataset coverage:** The full integration and scope validation documented here cover the 20 June sample. Other daily datasets still require processing and validation.
6. **Security interpretation:** A packet association is supporting evidence only. Analysts must assess the surrounding traffic and event context before drawing conclusions about suspicious or malicious behaviour.

## 5. Conclusion

PCAP-09 has been implemented and validated against the supplied 20 June EVE-JSON sample and its corresponding PCAP file.

The integration successfully processed all 56,331 events, attached evidence to every event, produced the expected status summary, and restricted all inspected candidate records to `2026-06-20.pcapng`.

The core integration objective is therefore complete for the tested dataset. Further work is required to investigate the high number of ambiguous and unmatched events, evaluate matching accuracy, and validate the workflow against the remaining daily datasets.

## 6. Related implementation files

- `pcap/extract_metadata.py` — extracts packet metadata from PCAP files.
- `pcap/build_index.py` — builds the SQLite metadata index.
- `pcap/filter_packets.py` — queries indexed packet metadata.
- `pcap/match_eve_events.py` — matches EVE events to PCAP candidates.
- `pcap/integrate_pcap_evidence.py` — creates enriched EVE-JSON output.
- `data/pcap_index/pcap_metadata.db` — SQLite PCAP metadata index.
- `data/enriched/eve_2026-06-20_with_pcap.jsonl` — validated enriched sample output.
- `docs/pcap_matching_validation.md` — detailed matching validation report.
