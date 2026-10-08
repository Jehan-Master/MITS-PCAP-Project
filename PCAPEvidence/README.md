# PCAP Evidence

Connects correlated MITS **cases** back to packet-level evidence in raw
`.pcap` / `.pcapng` captures, using TShark.

Suricata's `eve.json` events don't retain packet-level detail, and raw PCAP
files don't contain Suricata `flow_id` values — there's no direct key to join
them. This module bridges the two:

1. Reads each selected case's supporting EVE events from the database
   (`cases` → `case_findings` → `findings` → `events`).
2. Derives a network tuple (source/destination IP and port) and a time window
   from those events for each flow involved in the case.
3. Builds a TShark display filter from those tuples/windows and runs it
   against the supplied PCAP file(s).
4. Stores every matching packet's metadata back into the same SQLite
   database, linked to the case, so the dashboard (or anyone) can trace a
   case from alert → EVE event → the exact packets on the wire.

## Requirements

- Python 3.11+
- [TShark](https://www.wireshark.org/docs/wsug_html_chunked/AppToolstshark.html)
  (ships with Wireshark). Auto-detected via `PATH`, or at
  `C:\Program Files\Wireshark\tshark.exe` on Windows. Use `--tshark` to point
  at a specific binary.
- A SQLite database already populated by the main MITS pipeline
  (`Dashboard/analysis/pipeline.py`) — specifically the `cases`,
  `case_findings`, `findings`, and `events` tables.

## Usage

```bash
python -m PCAPEvidence.pcap_evidence --db database/mits.db --pcap-dir pcap
```

This processes every case in the database against every `.pcap`/`.pcapng`
file found (recursively) under `pcap/`.

### Common options

| Flag | Description |
|---|---|
| `--db PATH` | Shared SQLite database (default: `database/mits_test.db`) |
| `--pcap PATH` | A single PCAP/PCAPNG file. Repeatable. |
| `--pcap-dir PATH` | A directory of PCAP/PCAPNG files, searched recursively. Repeatable. |
| `--tshark PATH` | Explicit path to the TShark binary (auto-detected otherwise). |
| `--case-id ID` | Process only this case. Repeatable, to target a few specific cases. |
| `--limit N` | Process only the first N selected cases (useful for a quick test run). |
| `--time-padding SECONDS` | Seconds added before/after each flow's time window (default: `2.0`). |
| `--export-dir PATH` | Also export each case's matched packets as its own `.pcapng` file. |
| `--show-filter` | Print the TShark display filter built for each case before running it. |

### Examples

Dry-run the filter for a couple of cases without processing anything heavy:

```bash
python -m PCAPEvidence.pcap_evidence --db database/mits.db --pcap-dir pcap --show-filter --limit 2
```

Export standalone evidence captures per case, viewable directly in Wireshark:

```bash
python -m PCAPEvidence.pcap_evidence --db database/mits.db --pcap-dir pcap --export-dir evidence
```

Re-run (or target) a single case after fixing something:

```bash
python -m PCAPEvidence.pcap_evidence --db database/mits.db --pcap-dir pcap --case-id CASE-0009
```

## How filtering works

For each case, every supporting flow becomes one clause of a TShark display
filter: an endpoint match (source/destination IP and port, matched in either
direction) ANDed with a time window (padded by `--time-padding` on each
side). A case's full filter is the OR of all of its flow clauses.

Cases with a large number of flows can produce filters long enough to exceed
the host OS's command-line length limit when handed to TShark as a
subprocess (this showed up on Windows as `WinError 206: The filename or
extension is too long`). To avoid this, filters are automatically split into
batches that stay under a safe character limit; each batch is run as its own
TShark pass, and the results are merged and de-duplicated by frame number.
When this happens you'll see a line like:

```
filter split into 7 batches (too many selectors for a single TShark command line)
```

This is expected for cases with many flows and does not affect correctness
— every selector is still covered, just across more than one TShark call.
If `--export-dir` is used on a case that was split, you'll get one exported
file per batch (`CASE-0009-part1__capture.pcapng`,
`CASE-0009-part2__capture.pcapng`, …) rather than a single combined file;
merge them yourself with `mergecap` if you want one file:

```bash
mergecap -w evidence/CASE-0009-merged.pcapng evidence/CASE-0009-part*.pcapng
```

## PCAP file selection per case

Each case prefers PCAP files whose filename contains the case's date (in
`YYYY-MM-DD` form, derived from the case's first-seen timestamp, UTC). If no
filename matches, every supplied PCAP is searched instead.

## Output

Matches are written to a `pcap_evidence` table in the same SQLite database,
including (per matched packet): case ID, source PCAP file, frame number,
packet timestamp, direction, source/destination IP and port, protocol, and
any available HTTP (method/URI/status) or DNS query detail.

Re-running the tool is safe — already-stored packet references for a case
are not duplicated ("0 new evidence rows" on a repeat run is expected).

## Inspecting results

```bash
python -m PCAPEvidence.check_evidence --db database/mits.db
```

| Flag | Description |
|---|---|
| `--db PATH` | Database to read (default: `mits.db`) |
| `--case-id ID` | Only show evidence for this case |
| `--limit N` | Number of rows to print (default: 20) |

This prints stored evidence directly from the `pcap_evidence` table —
useful for a quick sanity check without opening Wireshark or a SQLite
browser.

## Opening evidence in Wireshark

- Easiest: run with `--export-dir` and open the resulting per-case
  `.pcapng` file(s) directly.
- Manual: open the original capture in Wireshark, then paste the filter
  printed by `--show-filter` into Wireshark's display filter bar. Wireshark
  itself has no command-line length limit, so an unbatched filter can be
  pasted there even if TShark couldn't take it as a single subprocess
  argument.
