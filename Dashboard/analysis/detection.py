import sqlite3
import warnings
from functools import lru_cache
from pathlib import Path

import numpy as np
import pandas as pd
import ipaddress
from project_paths import DATABASE_FILE

# Casting a tz-aware column to datetime64[ns] (done throughout this file,
# deliberately, to get consistent naive/UTC-equivalent timestamps across
# every rule -- see the comments near each .astype("datetime64[ns]") call)
# correctly converts the underlying instant but numpy warns that it can't
# label the result with a timezone. That's expected and harmless here, not
# a sign of a bug -- silence just this specific message rather than the
# call sites, so a genuinely new/unexpected warning elsewhere still surfaces.
warnings.filterwarnings(
    "ignore",
    message="no explicit representation of timezones available for np.datetime64",
    category=UserWarning,
)


DATABASE_PATH = DATABASE_FILE

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


def load_events_light(database_path=DATABASE_PATH):
    """Load only the columns R01/R02 actually use -- no "raw".

    "raw" holds the full per-event Suricata JSON (hundreds of bytes to a
    few KB each). At millions of rows that's gigabytes of pandas "object"
    dtype text. Dropping it *after* loading (as the column-selection inside
    build_high_connection_findings / build_multi_port_findings does) still
    pays the cost of reading and holding all of it in memory first -- on a
    machine with limited RAM headroom, that extra multi-GB footprint,
    stacked on top of the already-large full `events` frame these rules'
    caller keeps alive for R03/R04, is enough to push the process into
    swapping, which looks like a hang rather than a crash. Restricting the
    columns at the SQL level means that memory is simply never allocated
    for these two rules in the first place.
    """
    connection = get_connection(database_path)

    try:
        events = pd.read_sql_query(
            """
            SELECT
                id,
                ts,
                flow_id,
                src_ip,
                dest_ip,
                dest_port
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

        ts_values = source_flows["ts"].to_numpy().astype("datetime64[ns]")
        start_indices, end_indices = _rolling_forward_window_bounds(
            ts_values, HIGH_CONNECTION_WINDOW_SECONDS
        )
        flow_counts = end_indices - start_indices

        for start_index in range(len(source_flows)):
            flow_count = int(flow_counts[start_index])

            if flow_count >= HIGH_CONNECTION_THRESHOLD:
                window_start = source_flows.loc[start_index, "ts"]
                window = source_flows.iloc[
                    start_indices[start_index]:end_indices[start_index]
                ]
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
    """Detect and consolidate high connection rate episodes.

    Equivalent to building one raw finding per qualifying window and then
    merging overlapping ones (detect_high_connection_rate +
    consolidate_high_connection_findings), but computed directly per
    episode -- see _group_into_episodes for why this produces identical
    output without the O(n^2) rescans or the O(qualifying windows) finding
    objects the original two-step approach built.
    """
    import time
    _t0 = time.perf_counter()

    findings = []
    index = 0

    # This rule never reads "raw" (the full per-event Suricata JSON blob,
    # often hundreds of bytes to a few KB each). At ~2 million rows that
    # column alone can be gigabytes of pandas "object" dtype data (an array
    # of individual Python string pointers, not a contiguous buffer) --
    # every .copy() / .sort_values() / .drop_duplicates() below would
    # otherwise have to shuffle all of it around for a column this rule
    # never looks at. Selecting only the columns actually used drops that
    # cost before any of the heavier operations run.
    events = events[[
        "flow_id", "src_ip", "ts", "dest_ip",
    ]]

    flow_events = events[
        events["flow_id"].notna()
        & events["src_ip"].notna()
        & events["ts"].notna()
    ].copy()

    flows = (
        flow_events
        .sort_values("ts")
        .drop_duplicates(subset=["flow_id"])
    )
    print(f"    [R01 diag] distinct-flow dedup: {time.perf_counter()-_t0:.2f}s -> {len(flows):,} flows, {flows['src_ip'].nunique():,} distinct sources")
    _t0 = time.perf_counter()

    # A source with fewer total flows than the threshold can never produce
    # a qualifying window, so excluding it costs nothing in correctness.
    source_flow_counts = flows["src_ip"].value_counts()
    qualifying_sources = source_flow_counts[
        source_flow_counts >= HIGH_CONNECTION_THRESHOLD
    ].index
    flows = flows[flows["src_ip"].isin(qualifying_sources)]
    print(f"    [R01 diag] pre-filter (>= {HIGH_CONNECTION_THRESHOLD} flows): {time.perf_counter()-_t0:.2f}s -> {len(flows):,} flows survive, {flows['src_ip'].nunique():,} distinct sources survive")
    _t0 = time.perf_counter()

    if flows.empty:
        return []

    # Sort once by (source, time) and process every remaining source in a
    # single vectorized pass instead of Python-looping over a `groupby` --
    # with tens of thousands of distinct, moderately-active source IPs (not
    # just a few heavy ones), the per-group pandas materialization cost in
    # that loop, multiplied by the group count, was the real remaining
    # bottleneck, independent of how fast each individual group's own math
    # already was.
    flows = flows.sort_values(["src_ip", "ts"], kind="mergesort").reset_index(drop=True)
    group_ids, source_ip_values = pd.factorize(flows["src_ip"], sort=False)
    # pandas may store "ts" at microsecond (not nanosecond) resolution
    # depending on how the DataFrame was built -- casting to datetime64[ns]
    # explicitly before pulling out int64 values guarantees nanosecond
    # units regardless, so the window-width math below (which assumes
    # nanoseconds) is correct either way instead of silently being off by
    # 1000x on a microsecond-resolution column.
    ts_ns = flows["ts"].to_numpy().astype("datetime64[ns]").astype("int64")
    print(f"    [R01 diag] sort + factorize + ts cast: {time.perf_counter()-_t0:.2f}s")
    _t0 = time.perf_counter()

    start_indices, end_indices = _rolling_forward_window_bounds_multi_group(
        ts_ns, group_ids, HIGH_CONNECTION_WINDOW_SECONDS
    )
    flow_counts = end_indices - start_indices
    print(f"    [R01 diag] vectorized window bounds (all sources at once): {time.perf_counter()-_t0:.2f}s")
    _t0 = time.perf_counter()
    _boundaries = _group_boundaries(group_ids)
    print(f"    [R01 diag] group boundary computation: {time.perf_counter()-_t0:.2f}s -> {len(_boundaries):,} groups to loop over")
    _t0 = time.perf_counter()
    _episode_loop_count = 0

    for lo, hi in _boundaries:
        _episode_loop_count += 1
        if _episode_loop_count % 50000 == 0:
            print(f"    [R01 diag] ...{_episode_loop_count:,}/{len(_boundaries):,} groups processed, {time.perf_counter()-_t0:.2f}s elapsed so far")
        source_ip = source_ip_values[group_ids[lo]]

        episodes = _group_into_episodes(
            ts_ns[lo:hi],
            start_indices[lo:hi] - lo,
            end_indices[lo:hi] - lo,
            flow_counts[lo:hi],
            HIGH_CONNECTION_THRESHOLD,
        )

        for episode in episodes:
            index += 1
            member_slice = flows.iloc[
                lo + episode["slice_start"]:lo + episode["slice_end"]
            ]

            findings.append(
                create_finding(
                    rule_id="R01",
                    rule_name="High Connection Rate",
                    timestamp=pd.Timestamp(episode["start"]),
                    source_ip=source_ip,
                    description=(
                        f"Source repeatedly exceeded the threshold "
                        f"of {HIGH_CONNECTION_THRESHOLD} flows "
                        f"within {HIGH_CONNECTION_WINDOW_SECONDS} "
                        "seconds."
                    ),
                    priority="Medium",
                    flow_ids=sorted(member_slice["flow_id"].tolist()),
                    details={
                        "episode_id": f"R01-{index:04d}",
                        "episode_start": pd.Timestamp(episode["start"]),
                        "episode_end": pd.Timestamp(episode["end"]),
                        "max_flow_count": episode["max_value"],
                        "max_flow_timestamp": pd.Timestamp(episode["max_timestamp"]),
                        "total_flows": len(member_slice),
                        "destination_ips": sorted(
                            member_slice["dest_ip"].dropna().unique().tolist()
                        ),
                    },
                )
            )

    print(f"    [R01 diag] episode-building loop total: {time.perf_counter()-_t0:.2f}s -> {len(findings)} findings")

    return findings

@lru_cache(maxsize=None)
def is_internal_ip(ip_address):
    """Return whether an IP belongs to a configured internal network.

    Cached because this is called once per event row via .apply(), but
    honeypot traffic typically involves a small set of distinct IPs
    repeated across millions of rows -- caching turns that into one
    ipaddress.ip_address() parse per *unique* IP instead of per row.
    """
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


def _rolling_forward_window_bounds(ts_values, window_seconds):
    """For each i, the [start, end) index range of events within
    window_seconds *forward* of ts_values[i] (inclusive on both ends,
    matching the original `ts >= window_start & ts <= window_end` filter).

    ts_values must be sorted ascending (a numpy datetime64 array).

    The naive approach re-scans/re-filters the whole array for every i,
    which is O(n^2) per source group -- the actual cause of multi-hour
    runs on large datasets. Since the array is sorted, both the start
    index (first row with the same timestamp as ts_values[i], to
    correctly include timestamp ties regardless of row order) and the
    end index (first row past the window) can be found with a single
    vectorized binary search across every i at once: O(n log n) total,
    done in optimized C code rather than a Python loop.
    """
    window_ends = ts_values + np.timedelta64(window_seconds, "s")
    start_indices = np.searchsorted(ts_values, ts_values, side="left")
    end_indices = np.searchsorted(ts_values, window_ends, side="right")
    return start_indices, end_indices


def _group_boundaries(group_ids):
    """Return (lo, hi) index pairs for each contiguous run in a sorted
    (non-decreasing) group_ids array -- the global-array equivalent of what
    pandas groupby would hand you per iteration, without pandas building a
    sub-DataFrame for each one."""
    n = len(group_ids)
    if n == 0:
        return []
    change_points = np.flatnonzero(np.diff(group_ids)) + 1
    bounds = np.concatenate(([0], change_points, [n]))
    return list(zip(bounds[:-1], bounds[1:]))


def _rolling_forward_window_bounds_multi_group(ts_values_ns, group_ids, window_seconds):
    """Like _rolling_forward_window_bounds, but for ALL source groups in a
    single vectorized pass instead of looping per group in Python.

    Preconditions: rows are sorted by (group, ts) already, ts_values_ns is
    int64 nanoseconds since epoch, and group_ids is a non-decreasing integer
    array (e.g. from pd.factorize on a frame already sorted by source IP).

    Looping over tens of thousands of distinct source IPs in Python -- even
    with cheap per-group work -- still pays real per-iteration pandas
    overhead (materializing a group's sub-DataFrame) multiplied by the
    group count. This instead builds one combined sort key
    (group_id * multiplier + offset-within-that-group) large enough that
    crossing a group boundary always changes the key by more than any
    possible window width, so a single pair of vectorized searchsorted
    calls finds every row's window bounds across every group at once, with
    no per-group Python loop.

    The offset is each row's distance from its *own* group's earliest
    timestamp, not the dataset's global earliest timestamp. Using a global
    reference would require multiplier to exceed the *entire capture's*
    time span, and multiplying that by a large group count risks silently
    overflowing int64 on a long-running capture with many sources -- this
    happened in practice (a capture of several weeks, with low thousands of
    groups, was enough). Using each group's own span instead bounds
    multiplier by the single *longest-running* group's own activity
    window, which is typically far smaller than the full capture.

    As a final safeguard -- since it's still possible for one source to be
    active for the entire capture -- this explicitly checks whether the
    required multiplier could overflow int64 before committing to the
    vectorized path, and falls back to the always-correct (if slower)
    per-group loop when it's not safely verifiable. Silently wrong results
    from a bad composite key are far worse than a known, honest fallback.
    """
    ts_values_ns = np.asarray(ts_values_ns, dtype=np.int64)
    group_ids = np.asarray(group_ids, dtype=np.int64)
    n = len(ts_values_ns)

    if n == 0:
        return ts_values_ns.copy(), ts_values_ns.copy()

    boundaries = _group_boundaries(group_ids)

    group_min = np.empty(n, dtype=np.int64)
    for lo, hi in boundaries:
        group_min[lo:hi] = ts_values_ns[lo]

    local_offset = ts_values_ns - group_min
    window_ns = int(window_seconds) * 1_000_000_000
    max_local_span = int(local_offset.max()) + 1
    multiplier = max_local_span + window_ns + 1
    max_group_id = int(group_ids.max())

    # INT64_MAX with a comfortable safety margin (half of it) rather than
    # cutting it exactly at the limit.
    SAFE_INT64_MAX = (2**63 - 1) // 2
    if max_group_id > 0 and multiplier > SAFE_INT64_MAX // max_group_id:
        return _rolling_forward_window_bounds_per_group_fallback(
            ts_values_ns, group_ids, window_seconds, boundaries
        )

    composite = group_ids * multiplier + local_offset
    window_end_composite = composite + window_ns

    start_indices = np.searchsorted(composite, composite, side="left")
    end_indices = np.searchsorted(composite, window_end_composite, side="right")
    return start_indices, end_indices


def _rolling_forward_window_bounds_per_group_fallback(
    ts_values_ns, group_ids, window_seconds, boundaries
):
    """Always-correct fallback for _rolling_forward_window_bounds_multi_group:
    the same per-group searchsorted approach as the single-group version,
    just looped using cheap numpy slicing (via precomputed group
    boundaries) instead of pandas groupby. Used only in the rare case where
    the vectorized composite-key approach's multiplier could overflow
    int64; everywhere else the composite-key path is used instead."""
    n = len(ts_values_ns)
    start_indices = np.empty(n, dtype=np.int64)
    end_indices = np.empty(n, dtype=np.int64)

    for lo, hi in boundaries:
        # _rolling_forward_window_bounds expects datetime64, not raw int64
        # nanoseconds (it adds a np.timedelta64 to the array directly).
        sub_ts = ts_values_ns[lo:hi].astype("datetime64[ns]")
        sub_start, sub_end = _rolling_forward_window_bounds(sub_ts, window_seconds)
        start_indices[lo:hi] = sub_start + lo
        end_indices[lo:hi] = sub_end + lo

    return start_indices, end_indices


def _distinct_count_in_windows(values, start_indices, end_indices):
    """For each i, the number of distinct values in
    values[start_indices[i]:end_indices[i]].

    Both start_indices and end_indices are non-decreasing in i (guaranteed
    by _rolling_forward_window_bounds on sorted, fixed-size forward
    windows), so a single left/right pointer pass computes every window's
    distinct-value count in O(n) total -- each element is added to the
    window and removed from it at most once across the whole scan --
    instead of materializing and `.unique()`-ing a window slice for every
    single i (the actual cost behind the still-slow R02 benchmark).
    """
    n = len(values)
    counts = np.empty(n, dtype=np.int64)
    frequency = {}
    distinct = 0
    window_left = 0
    window_right = 0

    for i in range(n):
        new_right = end_indices[i]
        while window_right < new_right:
            value = values[window_right]
            if value in frequency:
                frequency[value] += 1
            else:
                frequency[value] = 1
                distinct += 1
            window_right += 1

        new_left = start_indices[i]
        while window_left < new_left:
            value = values[window_left]
            frequency[value] -= 1
            if frequency[value] == 0:
                del frequency[value]
                distinct -= 1
            window_left += 1

        counts[i] = distinct

    return counts


def _group_into_episodes(ts_values, start_indices, end_indices, metric_values, threshold):
    """Group qualifying (metric_values >= threshold) windows into episodes,
    exactly matching what building one raw finding per qualifying window
    and then merging overlapping raw findings (the original two-step
    detect_*/consolidate_* approach) would produce -- but computed directly
    from the arrays, without ever materializing a finding object, or even a
    window slice, for each individually-qualifying window.

    This relies on two properties that hold for fixed-size forward windows
    over sorted timestamps: (1) window_end is non-decreasing in i, which is
    exactly what makes the original consolidation's "does this window's
    start fall at or before the running episode end" chaining rule
    equivalent to comparing each qualifying window only to the *previous*
    qualifying window; and (2) a maximal run of mutually-overlapping
    windows' combined member rows are always exactly the single contiguous
    slice from the first window's start to the last window's end -- so an
    episode's full set of flow IDs / destination IPs / ports / event IDs
    can be read directly off one slice instead of unioning many.

    Returns a list of dicts: start, end, max_value, max_timestamp (the
    timestamp of the first window achieving max_value, matching the
    original's strict ">" update rule), slice_start, slice_end.
    """
    qualifying = np.flatnonzero(metric_values >= threshold)
    if len(qualifying) == 0:
        return []

    window_start_q = ts_values[qualifying]
    window_end_q = ts_values[end_indices[qualifying] - 1]

    breaks = np.empty(len(qualifying), dtype=bool)
    breaks[0] = True
    if len(qualifying) > 1:
        breaks[1:] = window_start_q[1:] > window_end_q[:-1]

    episode_ids = np.cumsum(breaks) - 1

    episodes = []
    for episode_id in range(int(episode_ids[-1]) + 1):
        members = qualifying[episode_ids == episode_id]
        metrics_in_episode = metric_values[members]
        max_local = int(np.argmax(metrics_in_episode))

        episodes.append(
            {
                "start": ts_values[members[0]],
                "end": ts_values[end_indices[members[-1]] - 1],
                "max_value": int(metrics_in_episode[max_local]),
                "max_timestamp": ts_values[members[max_local]],
                "slice_start": int(start_indices[members[0]]),
                "slice_end": int(end_indices[members[-1]]),
            }
        )

    return episodes

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

        ts_values = source_flows["ts"].to_numpy().astype("datetime64[ns]")
        start_indices, end_indices = _rolling_forward_window_bounds(
            ts_values, MULTI_PORT_WINDOW_SECONDS
        )

        for start_index in range(len(source_flows)):
            window = source_flows.iloc[
                start_indices[start_index]:end_indices[start_index]
            ]

            destination_ports = sorted(
                int(port)
                for port in window["dest_port"].dropna().unique()
            )

            port_count = len(destination_ports)

            if port_count >= MULTI_PORT_THRESHOLD:
                window_start = source_flows.loc[start_index, "ts"]
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
    """Detect and consolidate multi-port activity episodes.

    Equivalent to detect_multi_port_activity + consolidate_multi_port_findings,
    but computed directly per episode. The distinct-port-count-per-window
    metric uses _distinct_count_in_windows (a single O(n) two-pointer pass)
    instead of re-slicing and .unique()-ing a window for every start index --
    this is the one rule whose per-window metric isn't a plain event count,
    so it's the one rule that needed more than _rolling_forward_window_bounds
    alone to avoid rescanning.
    """
    findings = []
    index = 0

    # Same reasoning as build_high_connection_findings: this rule never
    # reads "raw", so drop it (and other unused columns) before the
    # heavier filter/sort/dedup operations below have to carry it along.
    events = events[[
        "flow_id", "src_ip", "ts", "dest_ip", "dest_port",
    ]]

    flow_events = events[
        events["flow_id"].notna()
        & events["src_ip"].notna()
        & events["dest_ip"].notna()
        & events["dest_port"].notna()
        & events["ts"].notna()
    ].copy()

    flow_events = flow_events[
        ~flow_events["src_ip"].apply(is_internal_ip)
        & flow_events["dest_ip"].apply(is_internal_ip)
    ].copy()

    flows = (
        flow_events
        .sort_values("ts")
        .drop_duplicates(subset=["flow_id"])
    )

    # Same pre-filter as build_high_connection_findings: a source can't
    # have more distinct ports in any window than its total flow count, so
    # sources with fewer flows than the threshold are excluded before the
    # per-group loop (and its pandas group-materialization overhead) runs.
    source_flow_counts = flows["src_ip"].value_counts()
    qualifying_sources = source_flow_counts[
        source_flow_counts >= MULTI_PORT_THRESHOLD
    ].index
    flows = flows[flows["src_ip"].isin(qualifying_sources)]

    for source_ip, source_flows in flows.groupby("src_ip"):
        source_flows = source_flows.sort_values("ts").reset_index(drop=True)

        ts_values = source_flows["ts"].to_numpy().astype("datetime64[ns]")
        start_indices, end_indices = _rolling_forward_window_bounds(
            ts_values, MULTI_PORT_WINDOW_SECONDS
        )

        port_values = source_flows["dest_port"].astype("int64").to_numpy()
        port_counts = _distinct_count_in_windows(
            port_values, start_indices, end_indices
        )

        episodes = _group_into_episodes(
            ts_values, start_indices, end_indices, port_counts,
            MULTI_PORT_THRESHOLD,
        )

        for episode in episodes:
            index += 1
            member_slice = source_flows.iloc[
                episode["slice_start"]:episode["slice_end"]
            ]

            findings.append(
                create_finding(
                    rule_id="R02",
                    rule_name="Multi-Port Activity",
                    timestamp=episode["start"],
                    source_ip=source_ip,
                    description=(
                        f"Source contacted at least "
                        f"{MULTI_PORT_THRESHOLD} distinct "
                        f"destination ports within "
                        f"{MULTI_PORT_WINDOW_SECONDS} seconds."
                    ),
                    priority="Medium",
                    flow_ids=sorted(member_slice["flow_id"].tolist()),
                    details={
                        "episode_id": f"R02-{index:04d}",
                        "episode_start": episode["start"],
                        "episode_end": episode["end"],
                        "max_port_count": episode["max_value"],
                        "max_port_timestamp": episode["max_timestamp"],
                        "destination_ports": sorted(
                            int(p) for p in
                            member_slice["dest_port"].dropna().unique()
                        ),
                        "destination_ips": sorted(
                            member_slice["dest_ip"].dropna().unique().tolist()
                        ),
                        "total_flows": len(member_slice),
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
        & events["ts"].notna()
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

    source_event_counts = failed_auth["source_ip"].value_counts()
    qualifying_sources = source_event_counts[
        source_event_counts >= FAILED_AUTH_THRESHOLD
    ].index
    failed_auth = failed_auth[
        failed_auth["source_ip"].isin(qualifying_sources)
    ]

    findings = []

    for source_ip, source_events in failed_auth.groupby("source_ip"):
        source_events = source_events.reset_index(drop=True)

        ts_values = source_events["timestamp"].to_numpy().astype("datetime64[ns]")
        start_indices, end_indices = _rolling_forward_window_bounds(
            ts_values, FAILED_AUTH_WINDOW_SECONDS
        )
        window_sizes = end_indices - start_indices

        # Only the *first* qualifying window per source produces a
        # finding (the original loop used `break` right after it), so
        # there is no need to build a window for every start index --
        # just locate the first index that meets the threshold.
        qualifying = np.flatnonzero(window_sizes >= FAILED_AUTH_THRESHOLD)

        if len(qualifying):
            start_index = int(qualifying[0])
            window = source_events.iloc[
                start_indices[start_index]:end_indices[start_index]
            ]
            # Use the naive, UTC-equivalent values from ts_values rather
            # than the original DataFrame column directly: the original
            # column can be tz-aware (confirmed -- this project's eve.json
            # timestamps carry mixed offsets), and mixing tz-aware
            # timestamps from this rule with the naive ones every other
            # rule produces (via the same datetime64[ns] cast) breaks
            # sorting findings from different rules together later.
            window_start_ts = pd.Timestamp(ts_values[start_index])
            window_end_ts = pd.Timestamp(
                ts_values[
                    start_indices[start_index]:end_indices[start_index]
                ].max()
            )

            findings.append(
                create_finding(
                    rule_id="R03",
                    rule_name="Repeated Failed Authentication",
                    timestamp=window_start_ts,
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
                        "window_start": window_start_ts,
                        "window_end": window_end_ts,
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

        ts_values = source_events["ts"].to_numpy().astype("datetime64[ns]")
        start_indices, end_indices = _rolling_forward_window_bounds(
            ts_values, PROTOCOL_ANOMALY_WINDOW_SECONDS
        )

        for index in range(len(source_events)):
            window = source_events.iloc[
                start_indices[index]:end_indices[index]
            ]

            if len(window) >= PROTOCOL_ANOMALY_THRESHOLD:
                event = source_events.loc[index]
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
    """Detect and consolidate repeated protocol anomaly episodes.

    Equivalent to detect_repeated_protocol_anomalies +
    consolidate_protocol_anomaly_findings, computed directly per episode.
    anomaly_types is parsed from each episode's member rows exactly once
    (via the single contiguous slice), rather than being re-parsed once per
    overlapping raw window and then unioned at consolidation time.
    """
    import json

    findings = []
    index = 0

    anomaly_events = events[
        (events["event_type"] == "anomaly")
        & events["src_ip"].notna()
        & events["dest_ip"].notna()
        & events["ts"].notna()
    ].copy()

    if anomaly_events.empty:
        return []

    anomaly_events = anomaly_events[
        ~anomaly_events["src_ip"].apply(is_internal_ip)
        & anomaly_events["dest_ip"].apply(is_internal_ip)
    ].copy()

    if anomaly_events.empty:
        return []

    anomaly_events = anomaly_events.sort_values("ts")

    source_event_counts = anomaly_events["src_ip"].value_counts()
    qualifying_sources = source_event_counts[
        source_event_counts >= PROTOCOL_ANOMALY_THRESHOLD
    ].index
    anomaly_events = anomaly_events[
        anomaly_events["src_ip"].isin(qualifying_sources)
    ]

    for source_ip, source_events in anomaly_events.groupby("src_ip"):
        source_events = source_events.sort_values("ts").reset_index(drop=True)

        ts_values = source_events["ts"].to_numpy().astype("datetime64[ns]")
        start_indices, end_indices = _rolling_forward_window_bounds(
            ts_values, PROTOCOL_ANOMALY_WINDOW_SECONDS
        )
        counts = end_indices - start_indices

        episodes = _group_into_episodes(
            ts_values, start_indices, end_indices, counts,
            PROTOCOL_ANOMALY_THRESHOLD,
        )

        for episode in episodes:
            index += 1
            member_slice = source_events.iloc[
                episode["slice_start"]:episode["slice_end"]
            ]

            anomaly_types = []
            for raw_event in member_slice["raw"].dropna():
                try:
                    raw_data = json.loads(raw_event)
                except (TypeError, json.JSONDecodeError):
                    continue
                anomaly_type = raw_data.get("anomaly", {}).get("event")
                if anomaly_type:
                    anomaly_types.append(anomaly_type)

            event_ids = member_slice["id"].unique().tolist()
            flow_ids = member_slice["flow_id"].dropna().unique().tolist()

            findings.append(
                create_finding(
                    rule_id="R04",
                    rule_name="Repeated External Protocol Anomaly",
                    timestamp=episode["start"],
                    source_ip=source_ip,
                    description=(
                        f"External source repeatedly generated "
                        f"protocol anomalies within "
                        f"{PROTOCOL_ANOMALY_WINDOW_SECONDS} "
                        f"seconds."
                    ),
                    priority="Medium",
                    event_ids=sorted(event_ids),
                    flow_ids=sorted(flow_ids),
                    details={
                        "episode_id": f"R04-{index:04d}",
                        "episode_start": episode["start"],
                        "episode_end": episode["end"],
                        "max_anomaly_count": episode["max_value"],
                        "max_anomaly_timestamp": episode["max_timestamp"],
                        "anomaly_types": sorted(set(anomaly_types)),
                        "destination_ips": sorted(
                            member_slice["dest_ip"].dropna().unique().tolist()
                        ),
                        "destination_ports": sorted(
                            member_slice["dest_port"].dropna().unique().tolist()
                        ),
                        "total_events": len(event_ids),
                        "total_flows": len(flow_ids),
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