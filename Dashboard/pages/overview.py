import streamlit as st
import pandas as pd
import plotly.express as px

from data.fake_cases import FAKE_CASES
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
# Prepare case and event data
# --------------------------------------------------

# Case data is still based on the prototype data.
# Real case data will be connected once the
# prioritization and case presentation are finalized.

case_data = []

for case in FAKE_CASES:

    case_data.append(
        {
            "ID": case.get("id", "N/A"),
            "Type": case.get("type", "Unknown"),
            "Source IP": case.get("source_ip", "N/A"),
            "Priority": case.get("priority", "Unknown"),
            "Status": case.get("status", "Unknown"),
        }
    )


cases = pd.DataFrame(case_data)


# Load real events from the SQLite database.

events = get_events()


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


# Convert timestamps into datetime values.

events["Timestamp"] = pd.to_datetime(
    events["Timestamp"],
    errors="coerce",
)


# --------------------------------------------------
# Run implemented rule-based detection
# --------------------------------------------------

# Detection currently operates directly on the
# structured SQLite event data.

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


# Count unique underlying events identified by
# the implemented rule-based detection methods.

suspicious_event_ids = set()

for finding in all_findings:
    suspicious_event_ids.update(
        finding.get("event_ids", [])
    )

suspicious_event_count = len(
    suspicious_event_ids
)


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


# Total number of events

total_events = len(events)


# Number of events matching the current filters

filtered_event_count = len(filtered_events)


col1.metric(
    "Total Events",
    total_events
)

st.caption(
    f"{filtered_event_count:,} events match "
    "the current filters."
)


# Number of unique events identified by the
# implemented rule-based detection methods.

col2.metric(
    "Suspicious Events",
    suspicious_event_count
)


# Prioritization has not yet been implemented.

col3.metric(
    "Prioritized Cases",
    "Pending"
)


# MITRE ATT&CK mapping has not yet been implemented.

col4.metric(
    "ATT&CK Mappings",
    "Pending"
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


if cases.empty:

    st.info(
        "No cases are currently available."
    )

else:

    # Case prioritization has not yet been implemented,
    # so the prototype case ordering is retained for now.

    top_cases = cases.head(5)


    # Table header

    header_col1, header_col2, header_col3, header_col4, header_col5 = (
        st.columns([1, 2, 2, 1, 1])
    )

    header_col1.write("**ID**")
    header_col2.write("**Type**")
    header_col3.write("**Source IP**")
    header_col4.write("**Priority**")
    header_col5.write("**Status**")

    st.divider()


    # Table rows

    for _, case in top_cases.iterrows():

        col1, col2, col3, col4, col5 = (
            st.columns([1, 2, 2, 1, 1])
        )

        with col1:

            if st.button(
                case["ID"],
                key=f"overview_case_{case['ID']}",
                type="tertiary"
            ):

                st.session_state[
                    "selected_case"
                ] = case["ID"]

                st.switch_page(
                    "pages/case_detail.py"
                )

        col2.write(case["Type"])
        col3.write(case["Source IP"])
        col4.write(case["Priority"])
        col5.write(case["Status"])


# --------------------------------------------------
# Footer
# --------------------------------------------------

st.divider()

st.caption(
    "Prototype dashboard — case data and "
    "ATT&CK information still use example "
    "values or pending functionality."
)