import streamlit as st
import pandas as pd
import plotly.express as px

from data.database import get_events
from analysis.detection import (
    load_events as load_detection_events,
    build_high_connection_findings,
    build_multi_port_findings,
    detect_repeated_failed_authentication,
    build_protocol_anomaly_findings,
)

# --------------------------------------------------
# Page configuration
# --------------------------------------------------

st.set_page_config(
    page_title="MITS Honeynet Analysis",
    page_icon="🛡️",
    layout="wide"
)


# --------------------------------------------------
# Dashboard title
# --------------------------------------------------

st.title("MITS Honeynet Threat Analysis")

st.write(
    "Overview of analysed honeynet activity "
    "and detected suspicious behaviour."
)

# --------------------------------------------------
# Load real event data
# --------------------------------------------------

event_data_available = False
event_load_error = None

try:
    events = get_events()

    if events is None:
        events = pd.DataFrame()

    event_data_available = True

except Exception as error:
    events = pd.DataFrame()
    event_load_error = error
    st.error(f"Database error: {type(error).__name__}: {error}")

# No fake cases are loaded.
# Real case creation and prioritization are still pending.
cases = pd.DataFrame(
    columns=["ID", "Type", "Source IP", "Priority", "Status"]
)

# Rename database columns to match the dashboard naming.

events = events.rename(
    columns={
        "ts": "Timestamp",
        "event_type": "Event Type",
        "src_ip": "Source IP",
        "src_port": "Source Port",
        "dest_ip": "Destination IP",
        "dest_port": "Destination Port",
        "proto": "Protocol",
        "app_proto": "Application Protocol",
    }
)

# Ensure the dashboard's expected columns exist.
required_columns = [
    "Timestamp",
    "Event Type",
    "Source IP",
    "Source Port",
    "Destination IP",
    "Destination Port",
    "Protocol",
    "Application Protocol",
]

for column in required_columns:
    if column not in events.columns:
        events[column] = pd.NA

events["Timestamp"] = pd.to_datetime(
    events["Timestamp"],
    errors="coerce",
)

# --------------------------------------------------
# Run implemented rule-based detection
# --------------------------------------------------

suspicious_event_count = None
detection_error = None

try:
    detection_events = load_detection_events()

    r01_findings = build_high_connection_findings(
        detection_events
    )

    r02_findings = build_multi_port_findings(
        detection_events
    )

    r03_findings = detect_repeated_failed_authentication(
        detection_events
    )

    r04_findings = build_protocol_anomaly_findings(
        detection_events
    )

    all_findings = (
        r01_findings
        + r02_findings
        + r03_findings
        + r04_findings
    )

    suspicious_event_ids = set()

    for finding in all_findings:
        suspicious_event_ids.update(
            finding.get("event_ids", [])
        )

    suspicious_event_count = len(suspicious_event_ids)

except Exception as error:
    detection_error = error
    st.error(f"Detection error: {type(error).__name__}: {error}")

# --------------------------------------------------
# Event filters
# --------------------------------------------------

st.subheader("Event Filters")

filter_col1, filter_col2, filter_col3, filter_col4 = (
    st.columns(4)
)


# Event Type filter

with filter_col1:

    event_type_options = ["All"] + sorted(
        events["Event Type"]
        .dropna()
        .unique()
        .tolist()
    )

    selected_event_type = st.selectbox(
        "Event Type",
        event_type_options,
    )


# Protocol filter

with filter_col2:

    protocol_options = ["All"] + sorted(
        events["Protocol"]
        .dropna()
        .unique()
        .tolist()
    )

    selected_protocol = st.selectbox(
        "Protocol",
        protocol_options,
    )


# Source IP filter

with filter_col3:

    source_ip_options = ["All"] + sorted(
        events["Source IP"]
        .dropna()
        .unique()
        .tolist()
    )

    selected_source_ip = st.selectbox(
        "Source IP",
        source_ip_options,
    )


# Destination IP filter

with filter_col4:

    destination_ip_options = ["All"] + sorted(
        events["Destination IP"]
        .dropna()
        .unique()
        .tolist()
    )

    selected_destination_ip = st.selectbox(
        "Destination IP",
        destination_ip_options,
    )


# Apply filters

filtered_events = events.copy()


if selected_event_type != "All":

    filtered_events = filtered_events[
        filtered_events["Event Type"]
        == selected_event_type
    ]


if selected_protocol != "All":

    filtered_events = filtered_events[
        filtered_events["Protocol"]
        == selected_protocol
    ]


if selected_source_ip != "All":

    filtered_events = filtered_events[
        filtered_events["Source IP"]
        == selected_source_ip
    ]


if selected_destination_ip != "All":

    filtered_events = filtered_events[
        filtered_events["Destination IP"]
        == selected_destination_ip
    ]

# --------------------------------------------------
# Overview metrics
# --------------------------------------------------

st.subheader("Overview")

col1, col2, col3, col4 = st.columns(4)

col1.metric(
    "Total Events",
    f"{len(events):,}" if event_data_available else "Pending",
)

col2.metric(
    "Suspicious Events",
    (
        f"{suspicious_event_count:,}"
        if suspicious_event_count is not None
        else "Pending"
    ),
)

col3.metric(
    "Prioritized Cases",
    "Pending",
)

col4.metric(
    "ATT&CK Mappings",
    "Pending",
)

if not event_data_available:
    st.warning(
        "Real event data is unavailable. "
        "Event counts and charts are Pending."
    )

if detection_error is not None:
    st.warning(
        "Detection results are Pending because "
        "the detection module could not produce a result."
    )

# --------------------------------------------------
# Event charts
# --------------------------------------------------

chart_col1, chart_col2 = st.columns(2)


# --------------------------------------------------
# Event Timeline
# --------------------------------------------------

with chart_col1:

    st.subheader("Event Timeline")

    if events.empty:

        st.info(
            "No event data is currently available."
        )

    else:

        # Group events by day

        timeline_data = (
            filtered_events
            .dropna(subset=["Timestamp"])
            .assign(
                Date=lambda df: df["Timestamp"].dt.date
            )
            .groupby("Date")
            .size()
            .reset_index(name="Events")
        )

        timeline_data["Date"] = pd.to_datetime(
            timeline_data["Date"]
        )

        timeline_data = timeline_data.sort_values(
            "Date"
        )

        fig = px.bar(
            timeline_data,
            x="Date",
            y="Events",
            labels={
                "Date": "Date",
                "Events": "Events"
            }
        )

        fig.update_layout(
            height=300,
            margin=dict(
                t=20,
                b=20,
                l=20,
                r=20
            ),
            xaxis_title=None,
            yaxis_title="Events"
        )

        st.plotly_chart(
            fig,
            width="stretch"
        )


# --------------------------------------------------
# Event Types
# --------------------------------------------------

with chart_col2:

    st.subheader("Event Types")

    if events.empty:

        st.info(
            "No event data is currently available."
        )

    else:

        event_types = (
            filtered_events["Event Type"]
            .value_counts()
            .reset_index()
        )

        event_types.columns = [
            "Event Type",
            "Events"
        ]

        fig = px.pie(
            event_types,
            names="Event Type",
            values="Events",
            hole=0.35
        )

        fig.update_layout(
            showlegend=True,
            margin=dict(
                t=20,
                b=20,
                l=20,
                r=20
            )
        )

        st.plotly_chart(
            fig,
            width="stretch"
        )

# --------------------------------------------------
# Top Investigated Cases
# --------------------------------------------------

st.subheader("Top Investigated Cases")

st.info(
    "Pending — real case creation, prioritization, "
    "and case status are not yet connected."
)

# --------------------------------------------------
# Footer
# --------------------------------------------------

st.divider()

st.caption(
    "Prototype dashboard — case data and "
    "ATT&CK information still use example "
    "values or pending functionality."
)
