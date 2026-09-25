import streamlit as st
import pandas as pd
import plotly.express as px

from data.fake_cases import FAKE_CASES


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

case_data = []

event_data = []

for case in FAKE_CASES:

    # Store case-level information
    case_data.append(
        {
            "ID": case.get("id", "N/A"),
            "Type": case.get("type", "Unknown"),
            "Source IP": case.get("source_ip", "N/A"),
            "Priority": case.get("priority", "Unknown"),
            "Status": case.get("status", "Unknown")
        }
    )

    # Store event-level information
    for event in case.get("events", []):

        event_data.append(
            {
                "Case ID": case.get("id", "N/A"),
                "Timestamp": event.get("timestamp", "N/A"),
                "Case Type": event.get("type", "Unknown"),
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


cases = pd.DataFrame(case_data)
events = pd.DataFrame(event_data)


# Convert timestamps into datetime values
if not events.empty:
    events["Timestamp"] = pd.to_datetime(
        events["Timestamp"],
        errors="coerce"
    )


# --------------------------------------------------
# Overview metrics
# --------------------------------------------------

st.subheader("Overview")

col1, col2, col3, col4 = st.columns(4)


# Total number of events
total_events = len(events)


# In the current prototype, all events belong to
# detected suspicious cases.
suspicious_events = len(events)


# Number of cases currently represented
prioritized_cases = len(cases)


# Number of cases with an ATT&CK mapping
attack_mappings = sum(
    1
    for case in FAKE_CASES
    if case.get("attack_mapping")
)


col1.metric(
    "Total Events",
    total_events
)

col2.metric(
    "Suspicious Events",
    suspicious_events
)

col3.metric(
    "Prioritized Cases",
    prioritized_cases
)

col4.metric(
    "ATT&CK Mappings",
    attack_mappings
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
            events
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
# Case Types
# --------------------------------------------------

with chart_col2:

    st.subheader("Case Types")

    if cases.empty:

        st.info(
            "No case data is currently available."
        )

    else:

        # Count cases by detected case type
        event_types = (
            cases["Type"]
            .value_counts()
            .reset_index()
        )

        event_types.columns = [
            "Case Type",
            "Cases"
        ]

        fig = px.pie(
            event_types,
            names="Case Type",
            values="Cases",
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

    # Currently use the first five cases.
    # Later, this can be replaced by the actual
    # prioritization/ranking produced by the analysis pipeline.
    top_cases = cases.head(5)


    # Table header
    header_col1, header_col2, header_col3, header_col4, header_col5 = st.columns(
        [1, 2, 2, 1, 1]
    )

    header_col1.write("**ID**")
    header_col2.write("**Type**")
    header_col3.write("**Source IP**")
    header_col4.write("**Priority**")
    header_col5.write("**Status**")

    st.divider()


    # Table rows
    for _, case in top_cases.iterrows():

        col1, col2, col3, col4, col5 = st.columns(
            [1, 2, 2, 1, 1]
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
    "Prototype dashboard — metrics and case data "
    "currently use example values."
)