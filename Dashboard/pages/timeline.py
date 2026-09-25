import streamlit as st
import pandas as pd
import plotly.express as px

from datetime import timedelta

from data.fake_cases import FAKE_CASES


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

events = []

for case in FAKE_CASES:
    for event in case.get("events", []):
        events.append(
            {
                "Case ID": case["id"],
                "Timestamp": event.get("timestamp"),
                "Event Type": event.get("type", "Unknown"),
                "Source IP": event.get("source_ip", "N/A"),
                "Destination IP": event.get(
                    "destination_ip",
                    "N/A"
                ),
                "Destination Port": event.get(
                    "destination_port",
                    "N/A"
                ),
                "Protocol": event.get(
                    "protocol",
                    "N/A"
                ),
                "Priority": case.get(
                    "priority",
                    "Low"
                ),
                "Evidence": event.get(
                    "evidence",
                    "N/A"
                )
            }
        )


if not events:
    st.info("No events are currently available.")
    st.stop()


events_df = pd.DataFrame(events)

events_df["Timestamp"] = pd.to_datetime(
    events_df["Timestamp"]
)

events_df = events_df.sort_values(
    "Timestamp"
)


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
    priority_order = [
        "High",
        "Medium",
        "Low",
        "Info"
    ]

    filtered_events = filtered_events.copy()

    filtered_events["Priority"] = pd.Categorical(
        filtered_events["Priority"],
        categories=priority_order,
        ordered=True
    )

    fig = px.scatter(
        filtered_events,
        x="Timestamp",
        y="Priority",
        color="Priority",
        category_orders={
            "Priority": priority_order
        },
        hover_data={
            "Case ID": True,
            "Event Type": True,
            "Source IP": True,
            "Destination IP": True,
            "Destination Port": True,
            "Protocol": True,
            "Timestamp": True,
            "Priority": True
        }
    )

    fig.update_traces(
        marker=dict(
            size=9
        )
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
        yaxis_title=None,
        legend_title=None
    )

    st.plotly_chart(
        fig,
        width="stretch"
    )


# --------------------------------------------------
# Event table
# --------------------------------------------------

st.subheader("Events")


if filtered_events.empty:
    st.info(
        "No events are available for the selected timeframe."
    )

else:
    table_data = filtered_events.copy()

    table_data["Timestamp"] = (
        table_data["Timestamp"]
        .dt.strftime("%Y-%m-%d %H:%M:%S")
    )

    table_data["Details"] = table_data.apply(
        lambda row: (
            f'{row["Event Type"]} — '
            f'{row["Destination IP"]}:'
            f'{row["Destination Port"]} '
            f'({row["Protocol"]})'
        ),
        axis=1
    )

    table_data = table_data[
        [
            "Timestamp",
            "Event Type",
            "Source IP",
            "Details",
            "Priority"
        ]
    ]

    st.dataframe(
        table_data,
        width="stretch",
        hide_index=True
    )


# --------------------------------------------------
# Prototype notice
# --------------------------------------------------

st.divider()

st.caption(
    "Prototype dashboard — timeline data currently represents "
    "example values."
)