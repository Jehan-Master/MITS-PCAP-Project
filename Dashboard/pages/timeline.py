import streamlit as st
import pandas as pd
import plotly.express as px

from datetime import timedelta
from data.database import get_events

# --------------------------------------------------
# Page title
# --------------------------------------------------

st.title("Timeline")
st.write(
    "Chronological view of events identified by the threat "
    "analysis system."
)

# --------------------------------------------------
# Prepare event data
# --------------------------------------------------

events_df = get_events()

if events_df.empty:
    st.info("No network events are currently available.")
    st.stop()

# Rename database columns for the dashboard.
events_df = events_df.rename(
    columns={
        "id": "Event ID",
        "ts": "Timestamp",
        "event_type": "Event Type",
        "src_ip": "Source IP",
        "src_port": "Source Port",
        "dest_ip": "Destination IP",
        "dest_port": "Destination Port",
        "proto": "Protocol",
        "app_proto": "Application Protocol",
        "alert_sid": "Alert SID",
        "alert_signature": "Alert Signature",
        "alert_severity": "Alert Severity",
    }
)

# Parse mixed timestamp formats and normalize to UTC.
events_df["Timestamp"] = pd.to_datetime(
    events_df["Timestamp"],
    format="mixed",
    errors="coerce",
    utc=True,
)

# Remove records with invalid timestamps.
events_df = events_df.dropna(subset=["Timestamp"])

if events_df.empty:
    st.info("No network events with valid timestamps are available.")
    st.stop()

events_df = events_df.sort_values("Timestamp")

# --------------------------------------------------
# Determine available time range
# --------------------------------------------------

latest_timestamp = events_df["Timestamp"].max()

available_years = sorted(
    events_df["Timestamp"].dt.year.unique(),
    reverse=True
)

# --------------------------------------------------
# Timeframe selector
# --------------------------------------------------

selector_col1, selector_col2 = st.columns(
    [3, 1]
)

with selector_col2:
    timeframe_options = [
        "Last 24 hours",
        "Last 7 days",
        "Last 30 days"
    ]

    timeframe_options += [
        str(year)
        for year in available_years
    ]

    selected_timeframe = st.selectbox(
        "Timeframe",
        timeframe_options,
        label_visibility="collapsed"
    )


# --------------------------------------------------
# Filter events according to selected timeframe
# --------------------------------------------------

if selected_timeframe == "Last 24 hours":
    start_time = latest_timestamp - timedelta(hours=24)

    filtered_events = events_df[
        events_df["Timestamp"] >= start_time
    ]

elif selected_timeframe == "Last 7 days":
    start_time = latest_timestamp - timedelta(days=7)

    filtered_events = events_df[
        events_df["Timestamp"] >= start_time
    ]

elif selected_timeframe == "Last 30 days":
    start_time = latest_timestamp - timedelta(days=30)

    filtered_events = events_df[
        events_df["Timestamp"] >= start_time
    ]

else:
    selected_year = int(selected_timeframe)

    filtered_events = events_df[
        events_df["Timestamp"].dt.year == selected_year
    ]


# --------------------------------------------------
# Timeline graph
# --------------------------------------------------

st.subheader("Event Timeline")


if filtered_events.empty:
    st.info(
        "No events were found for the selected timeframe."
    )

else:
    fig = px.scatter(
        filtered_events,
        x="Timestamp",
        y="Event Type",
        color="Event Type",
        hover_data={
            "Event ID": True,
            "Event Type": True,
            "Source IP": True,
            "Source Port": True,
            "Destination IP": True,
            "Destination Port": True,
            "Protocol": True,
            "Application Protocol": True,
            "Alert SID": True,
            "Alert Signature": True,
            "Alert Severity": True,
            "Timestamp": True,
        },
    )

    fig.update_traces(
        marker=dict(size=9)
    )

    fig.update_layout(
        height=300,
        margin=dict(
            t=20,
            b=20,
            l=20,
            r=20,
        ),
        xaxis_title=None,
        yaxis_title=None,
        legend_title=None,
    )

    st.plotly_chart(
        fig,
        width="stretch",
    )

# --------------------------------------------------
# Event table
# --------------------------------------------------

st.subheader("Network Events")

if filtered_events.empty:
    st.info(
        "No network events are available "
        "for the selected timeframe."
    )

else:
    table_data = filtered_events.copy()

    table_data["Timestamp"] = (
        table_data["Timestamp"]
        .dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    )

    # Build Details using available alert information.
    #def format_event_details(row):
    #    if pd.notna(row["Alert Signature"]):
    #        return f'Alert: {row["Alert Signature"]}'

    #    return ""

    #table_data["Details"] = table_data.apply(
    #    format_event_details,
    #    axis=1,
    #"""

    table_data = table_data[
        [
            "Timestamp",
            "Event Type",
            "Source IP",
            "Destination IP",
            "Protocol",
            #"Details",
        ]
    ]

    st.dataframe(
        table_data,
        width="stretch",
        hide_index=True,
    )

# --------------------------------------------------
# Prototype notice
# --------------------------------------------------

st.divider()

st.caption(
    "Prototype dashboard — timeline data is generated from "
    "the current analysis results."
)