# Anomaly Detection

Statistical, unsupervised detection of unusual network behaviour from the
MITS SQLite `events` table (populated by `DataInitialFiltering/ingest.py` /
`analysis/ingest.py`). This runs independently of — and in addition to — the
rule-based detectors in `analysis/detection.py`.

## Method

For each source IP, events are bucketed into fixed-size time windows (default
60 seconds). Within each window, five metrics are tracked:

| Metric | What it counts |
|---|---|
| `event_count` | Total events from this source in the window |
| `unique_destinations` | Distinct destination IPs contacted |
| `unique_destination_ports` | Distinct destination ports contacted |
| `unique_flows` | Distinct flow IDs |
| `alert_count` | Events with `event_type == "alert"` |

A **baseline** (median and Median Absolute Deviation, MAD) is computed per
metric, preferring a **per-source baseline** built from that source's own
window history. If a source doesn't have enough windows yet
(`--min-source-windows`, default 5), a **global baseline** across all sources
is used instead — this is recorded per finding as `baseline_scope`.

Each window's observed value is then compared to its baseline using a
**modified z-score** (median + MAD based, robust to outliers unlike a
mean/stddev z-score). Any metric scoring above `--threshold` (default `3.5`)
produces an **anomaly finding**, with a human-readable `reason` explaining
which metric fired.

## Methodology

**1. Windowing.** Events are grouped by source IP into fixed, non-overlapping
time buckets of `--window-seconds` (default 60s). Each (source IP, window)
pair becomes one row in `anomaly_windows`, with the five metrics above
computed from the events that fell into it.

**2. Baselines (median + MAD).** For each metric, a baseline is a **median**
(the typical value) and a **Median Absolute Deviation**, MAD = `median(|x -
median(x)|)` (the typical spread). Median/MAD are used instead of mean/stddev
because they aren't dragged around by the extreme values that are exactly
what's being searched for — a few huge spikes don't inflate the baseline
and mask themselves the way they would with a mean/stddev approach.

- A **per-source baseline** is built per metric from that source's own
  window history, but only once it has at least `--min-source-windows`
  windows (default 5) — median/MAD on fewer points than that isn't
  considered reliable.
- A **global baseline** per metric is built across every window in the
  dataset regardless of source, and is used for any source that hasn't yet
  reached `--min-source-windows`. The global baseline's median/MAD are
  computed via direct order-statistics (sorted-value lookups) rather than
  Python's `statistics.median`, so it scales to large numbers of windows
  without first loading them all into memory at once.
- Which one applied is recorded on every finding as `baseline_scope`
  (`source` or `global`).

**3. Scoring (modified z-score).** Each window's observed value for a metric
is compared to its baseline with a **one-sided modified z-score**:

```
score = 0.6745 * (observed - baseline_median) / scale
```

0.6745 is the standard constant that makes MAD comparable to a normal
distribution's standard deviation. The score is one-sided: a value at or
below the baseline median always scores `0` — this detector only flags
unusually *high* activity (volume/fan-out spikes), never unusually low
activity. `scale` is normally the baseline's MAD, but since MAD is often
exactly `0` for low-count integer metrics (e.g. a source that almost always
makes exactly 2 connections per window), a fallback scale is substituted so
a genuine spike can still be scored instead of causing a divide-by-zero:
first the global baseline's MAD for that metric, and if that's also `0`,
`max(1.0, 10% of the baseline median)`.

**4. Findings.** Any metric whose score exceeds `--threshold` (default
`3.5`, a common robust-outlier starting point) becomes a row in
`anomaly_findings`, carrying the observed value, baseline median, score,
scope, and a plain-language `reason`. Each finding is also linked back to
the specific `events` rows that fed that window, via `anomaly_events`, for
drill-down evidence. Finding IDs are deterministic (a short hash of
detector name, source IP, window start, window size, and metric), so
re-running the same parameters against unchanged data reproduces the same
IDs rather than creating duplicates.

## Limitations

- **Volume/fan-out only, not behaviour.** The five metrics are all "how
  much" rather than "what" — none of them look at payload content, specific
  ports/protocols touched, geography, or sequencing. A slow, low-volume
  attack that never produces an unusual count in any window (e.g. one
  connection per window, consistently) will not be flagged, no matter how
  suspicious the destination or payload is.
- **One-sided by design.** Unusually *low* activity from a normally-active
  source (which can itself indicate compromise, e.g. a host going dark) is
  never flagged — only spikes above baseline are scored.
- **Per-metric, not joint.** Each metric is baselined and scored
  independently. A source that's simultaneously a little high on all five
  metrics — individually unremarkable, but suspicious in combination — won't
  necessarily trigger any single metric's threshold, since there's no
  combined/multivariate score.
- **Fixed, non-overlapping windows.** A burst that straddles a window
  boundary gets split across two windows and may not exceed the threshold in
  either one, even though the full burst would have. Smaller
  `--window-seconds` reduces this risk but needs more data before per-source
  baselines are reliable (see `--min-source-windows`).
- **Cold-start sources fall back to the global baseline**, which reflects
  "typical across the whole network" rather than "typical for this specific
  source." A source whose normal behaviour differs from the network average
  (e.g. a busy internal server) may get flagged early simply for being
  itself, until it accumulates enough windows for its own baseline to take
  over.
- **Baselines include the full history, anomalies and all.** Baselines are
  computed once per run from all available windows — they are not seeded
  from a known-clean period and don't exclude prior anomalous windows. A
  source with sustained anomalous behaviour throughout the dataset will have
  that behaviour partially absorbed into its own baseline, raising the bar
  for what counts as unusual for it specifically.
- **No seasonality/trend modelling.** There's no notion of time-of-day,
  day-of-week, or long-term trend — a median/MAD baseline from the whole
  dataset treats all time periods as equally "normal," so legitimate
  periodic spikes (e.g. a nightly batch job) can be scored as anomalies.
- **Sensitive to `--window-seconds` and `--threshold` choice**, and there's
  no automatic tuning — both are fixed CLI parameters the operator sets, and
  the right values depend on the traffic pattern and baseline data available
  (see Tuning notes below).
- **Unsupervised, no ground truth.** Findings are statistical outliers
  relative to observed history, not confirmed malicious activity — they
  still need triage (e.g. cross-referencing with `analysis/detection.py`'s
  rule-based findings or PCAP evidence) before being treated as verified
  incidents.

## Requirements

- Python 3.11+
- A SQLite database already containing the `events` table (populated by the
  ingestion step of the main MITS pipeline).

## Usage

```bash
python -m AnomalyDetection.anomaly_detection --db mits.db
```

### Options

| Flag | Description |
|---|---|
| `--db PATH` | SQLite database to analyse (default: `mits.db`) |
| `--window-seconds N` | Fixed aggregation window size, in seconds (default: `60`) |
| `--threshold N` | Modified z-score threshold to flag a finding (default: `3.5`) |
| `--min-source-windows N` | Minimum windows needed before a source gets its own baseline; otherwise falls back to the global baseline (default: `5`) |
| `--top N` | Print the N highest-scoring findings after the run (default: `10`) |

### Example

Wider windows, stricter threshold, see the top 20 results:

```bash
python -m AnomalyDetection.anomaly_detection --db database/mits.db --window-seconds 120 --threshold 4.0 --top 20
```

This step is also invoked automatically as part of the full pipeline via:

```bash
python -m Dashboard.analysis.pipeline --db database/mits.db --with-anomaly
```

## Output tables

Results are written into the same SQLite database, across several tables:

- **`anomaly_windows`** — one row per (source IP, time window), with the raw
  metric values for that window.
- **`anomaly_baselines`** — the computed median/MAD baseline per metric, per
  source (or global).
- **`anomaly_findings`** — one row per metric that exceeded the threshold in
  a given window: observed value, baseline median, anomaly score,
  `baseline_scope` (`source` or `global`), and a `reason` string.
- **`anomaly_events`** — links each finding back to the specific `events`
  rows that contributed to that window, for drill-down/evidence.
- **`anomaly_runs`** — one row per execution of the detector, recording the
  parameters used (window size, threshold, min source windows) and a run ID,
  for reproducibility and comparing runs over time.

Re-running the detector rebuilds these tables fresh each time (safe to
re-run after ingesting more data).

## Inspecting results

```bash
python -m AnomalyDetection.check_anomalies --db mits.db
```

| Flag | Description |
|---|---|
| `--db PATH` | Database to read (default: `mits.db`) |
| `--source IP` | Only show findings for this source IP |
| `--limit N` | Number of rows to print (default: 20) |

Each row shows the finding ID, source IP, window start, the metric and
observed value vs. baseline, the anomaly score, and the number of supporting
`events` rows linked as evidence — useful for a quick sanity check without
a SQLite browser.

## Tuning notes

- **Smaller `--window-seconds`** → more, shorter windows; better for
  catching short bursts, but needs more windows before a per-source baseline
  is trustworthy (see `--min-source-windows`).
- **Lower `--threshold`** → more findings, including more false positives.
  `3.5` is a common "robust outlier" starting point for modified z-scores;
  tune based on how many findings come back on your dataset.
- Sources with very few events will mostly fall back to the **global**
  baseline until they accumulate `--min-source-windows` windows of their
  own — expect more `global`-scoped findings early in a capture, and more
  `source`-scoped ones as history builds up.
