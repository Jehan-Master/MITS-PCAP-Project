# PCAP–EVE Matching Validation Report

## 1. Purpose and scope

This report records a preliminary validation of the PCAP–EVE event matching method using eight selected events from `input/eve_2026-06-20.json` and the corresponding packet capture `input/2026-06-20.pcapng`. Two additional edge-case checks were run to verify the `unmatched` and `invalid_event` outcomes.

The objective is to check whether the matcher can associate EVE events with relevant packet metadata, whether independent inspection of the PCAP supports the event details, and whether the matcher handles two basic unsuccessful-input cases as expected. These checks do not establish a dataset-wide accuracy rate.

## 2. Matching methodology

The matcher compares an EVE event with packet metadata using the directional five-tuple (source IP, source port, destination IP, destination port, and transport protocol) and a timestamp window. The default timestamp tolerance is ±0.5 seconds. Candidate packets are ranked by timestamp difference and protocol context.

Protocol context is derived from available EVE event fields, including `event_type`, `app_proto`, and, when present as a nested object, `anomaly.app_proto`. This context helps rank candidates; it does not override the tuple and timestamp filters or guarantee that a candidate contains the application payload associated with the event.

Possible matcher outcomes:

- `matched`: one candidate was returned.
- `ambiguous`: multiple candidates were returned, so unique packet-level attribution was not established.
- `unmatched`: no candidate was found within the configured criteria.
- `invalid_event`: required event data was missing or invalid.

A matcher status describes the matching procedure's result. It does not, by itself, establish maliciousness or prove that all application-level event details are corroborated.

## 3. Selected validation cases

### V01 — SSH

**EVE source:** Line 1  
**Matcher result:** `ambiguous` (10 candidates)

Independent inspection found SSH-dissection evidence in multiple packets from the same connection, including frames 26272, 26273, and 26276. This supports the connection-level event, but multiple candidates prevent unique packet-level attribution.

**Assessment:** Connection-level evidence corroborated; exact packet attribution remains ambiguous.

### V02 — HTTP

**EVE source:** Line 253  
**Matcher result:** `ambiguous` (6 candidates)

Frame 28972 contains the HTTP request `GET /SDK/webLanguage` and occurs approximately 48 ms before the EVE event timestamp. Some candidates at the exact EVE timestamp contain no TCP payload and are dissected only as TCP. A timestamp-near packet may therefore not contain the application data described by an event. Frame 28972 has matching protocol context, but that ranking signal does not make the result unique.

**Assessment:** HTTP request corroborated in the connection; exact packet attribution remains ambiguous.

### V03 — Fileinfo

**EVE source:** Line 254  
**Matcher result:** `matched` (1 candidate, frame 28985)

The EVE event describes the `/SDK/webLanguage` HTTP transaction, with status 404 and a reported size of 275 bytes. Inspection of the corresponding TCP stream found an HTTP response for that path with status 404 and a 275-byte response. The selected candidate frame itself has no TCP payload, so corroboration comes from the broader transaction. The PCAP inspection does not independently verify all EVE file-state fields, such as `stored` or `state`.

**Assessment:** Transaction-level details corroborated; not every fileinfo field independently verified.

### V04 — Anomaly

**EVE source:** Line 540  
**Matcher result:** `ambiguous` (5 candidates)

The EVE anomaly is `REQUEST_HEADER_REPETITION`. Inspection of the same TCP stream found an HTTP request containing two `Connection` headers (`keep-alive` and `close`) in frame 31897. That frame occurs approximately 42 microseconds before the EVE event timestamp. The exact-timestamp candidate, frame 31898, contains no TCP payload. After protocol-context handling was updated to include the nested `anomaly.app_proto` field, frame 31900 was flagged as having matching HTTP protocol context. This improves the contextual ranking signal but does not change the ambiguous status or uniquely identify the packet containing the request.

**Assessment:** PCAP evidence supports the repeated-header anomaly at the HTTP-request level; exact packet attribution remains ambiguous.

### V05 — DNS

**EVE source:** Line 10693  
**Matcher result:** `matched` (1 candidate, frame 147513)

The candidate agrees with the EVE event on timestamp, endpoints, UDP transport, query name (`_https._tcp.download.docker.com`), and query type SRV (33). The packet is dissected as DNS.

**Assessment:** Timestamp, tuple, and selected DNS fields corroborated.

### V06 — TLS

**EVE source:** Line 10723  
**Matcher result:** `ambiguous` (13 candidates)

Inspection of the same connection found a TLS ClientHello with SNI `motd.ubuntu.com` in frame 147546 and certificate evidence with subject `motd.ubuntu.com` and issuer Let's Encrypt R12 in frame 147568. The exact-timestamp candidate, frame 147573, contains no TCP payload. The certificate fingerprint was not independently compared.

**Assessment:** TLS connection details corroborated; exact packet attribution remains ambiguous.

### V07 — FTP

**EVE source:** Line 16056  
**Matcher result:** `ambiguous` (2 candidates)

Frame 215987 contains the TCP payload `USER test` followed by a newline, matching the EVE command and command data. Frame 215988 contains `Login incorrect` followed by a `login:` prompt, consistent with the EVE response information. Frame 215987 occurs approximately 176.235 ms before the EVE event timestamp. Frame 215994 has the exact EVE timestamp but contains no TCP payload.

**Assessment:** Command and response corroborated at the connection level; exact packet attribution remains ambiguous.

### V08 — mDNS

**EVE source:** Line 775  
**Matcher result:** `matched` (1 candidate, frame 33198)

The candidate agrees with the EVE event on timestamp, ports, IPv6 endpoints after address normalization, and protocol dissection as mDNS over UDP. This case also shows why normalizing equivalent IPv6 address representations matters. The mDNS application contents were not independently validated in this check.

**Assessment:** Timestamp, tuple, and protocol corroborated; application-level fields not independently verified.

## 4. Edge-case validation

Two additional tests were run using the existing `match_eve_event()` function and indexed PCAP metadata. These were temporary checks and did not require changing the matching algorithm.

### E01 — Valid event with no matching packet

**Input:** A structurally valid event with a directional tuple using source `203.0.113.1:65000` and destination `198.51.100.2:65001`, TCP, timestamp `2026-06-20T12:00:00+00:00`.

**Actual result:**
- Status: `unmatched`
- Candidate count: `0`
- Test assertion: passed

**Assessment:** The matcher returned `unmatched` when no packet candidate satisfied the configured matching criteria in the index.

### E02 — Event missing a required field

**Input:** An event with a timestamp and other connection fields, but without `src_ip`.

**Actual result:**
- Status: `invalid_event`
- Reason: `Missing required fields: src_ip`
- Candidate count: `0`
- Test assertion: passed

**Assessment:** The matcher detected the missing required field and returned `invalid_event` with an explanatory reason.

These two checks cover the basic `unmatched` and `invalid_event` paths tested here. They do not exhaustively test every possible invalid value or malformed event.

## 5. Summary of observations

Across the eight selected event cases:

- The matcher returned `matched` for V03 (fileinfo), V05 (DNS), and V08 (mDNS).
- The matcher returned `ambiguous` for V01 (SSH), V02 (HTTP), V04 (anomaly), V06 (TLS), and V07 (FTP).
- Independent PCAP inspection found supporting evidence for the described event or its connection in all eight cases, with the scope of corroboration varying by event type.
- Several events have an exact-timestamp candidate without application payload, while relevant application evidence appears in nearby packets in the same TCP stream.
- Protocol-context matching helps distinguish candidates when event context is available, but does not eliminate ambiguity where several packets fit the tuple and time criteria.
- A single EVE event can correspond to several packets, and unique packet-level matching is not always appropriate for connection-oriented protocols.

The two edge-case checks also returned the expected `unmatched` and `invalid_event` statuses.

These findings are descriptive results from eight selected cases and two edge-case checks, not a statistically representative sample. They must not be presented as an overall matching-accuracy percentage.

## 6. Limitations

1. **Small, selected sample:** The eight event cases were selected for manual inspection and are not a random sample of the full dataset.
2. **Packet versus connection evidence:** Corroboration in a TCP stream does not necessarily identify one unique packet as the source of an EVE event.
3. **Timestamp proximity:** An exact or near timestamp does not guarantee that a candidate packet contains the application payload relevant to the event.
4. **Application dissection:** Protocol decoding can vary by port, heuristic, and packet context. Some application data may appear as generic TCP payload.
5. **Partial field verification:** The checks did not independently verify every field of every EVE event. Conclusions are limited to the fields explicitly inspected.
6. **Not a maliciousness verdict:** Matching and corroboration establish relationships between records and packet evidence; they do not independently prove malicious intent.
7. **Dataset coverage:** This validation covers selected events from the 2026-06-20 EVE file and PCAP only. It does not establish performance on other dates, event types, or the full dataset.
8. **Edge-case coverage:** The two edge-case checks verify one unmatched input and one event missing a required field. They do not exhaustively test malformed timestamps, invalid ports, unsupported protocols, all missing-field combinations, or every exception path.

## 7. Assessment and conclusion

For the scope tested, PCAP-08 validation is complete: the eight selected cases were compared with independently inspected PCAP evidence, the observed `matched` and `ambiguous` outcomes were recorded without forcing ambiguous cases into unique matches, and one `unmatched` case and one `invalid_event` case returned their expected outcomes.

The results indicate that the matcher can retrieve useful packet candidates and that manual PCAP inspection can corroborate event details even when the matcher returns `ambiguous`. They also show that packet-level matching and connection-level evidence should be distinguished in downstream analysis.

The validation does not establish overall matching accuracy, performance across the full dataset, or complete correctness for every possible input.

A potential future improvement is to represent these as separate concepts:

- **Match status:** `matched`, `ambiguous`, `unmatched`, or `invalid_event`.
- **Evidence scope:** packet-level evidence, connection-level evidence, or not independently corroborated.
- **Verification notes:** the fields and frames that support the assessment, including known limitations.

This is a proposed improvement, not an implemented feature. Any code changes should be evaluated and tested separately before being described as completed.
