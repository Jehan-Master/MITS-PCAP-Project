import streamlit as st
import pandas as pd

from data.analysis_data import (
    get_case,
    get_case_findings,
    get_events_by_ids,
    get_events_by_flow_ids,
)


# --------------------------------------------------
# Find the selected case
# --------------------------------------------------

selected_case_id = st.session_state.get("selected_case")

if not selected_case_id:
    st.warning("No case has been selected.")

    if st.button("← Cases"):
        st.switch_page("pages/cases.py")

    st.stop()


case = get_case(selected_case_id)

if case is None:
    st.error("The selected case could not be found.")

    if st.button("← Cases"):
        st.switch_page("pages/cases.py")

    st.stop()


findings = get_case_findings(selected_case_id)


# --------------------------------------------------
# Top navigation bar
# --------------------------------------------------

header_col1, header_col2 = st.columns([1, 1])

with header_col1:
    if st.button(
        "← Cases",
        key="back_to_cases",
        type="secondary"
    ):
        st.switch_page("pages/cases.py")

with header_col2:
    st.markdown(
        f"""
        <div style="
            text-align: right;
            font-weight: 600;
            padding-top: 0.4rem;
        ">
            {case["case_id"]}
        </div>
        """,
        unsafe_allow_html=True
    )


# --------------------------------------------------
# Case header
# --------------------------------------------------

header_col1, header_col2 = st.columns([3, 1])

with header_col1:
    st.title("Candidate Case")

with header_col2:
    st.markdown(
        """
        <div style="
            text-align: right;
            font-size: 1.1rem;
            font-weight: 700;
            padding-top: 1.2rem;
        ">
            PENDING
        </div>
        """,
        unsafe_allow_html=True
    )


# --------------------------------------------------
# Calculate case summary information
# --------------------------------------------------

source_ips = case["source_ips"]

if source_ips:
    source_ip = ", ".join(source_ips)
else:
    source_ip = "N/A"

first_seen = case["first_seen"] or "N/A"
last_seen = case["last_seen"] or "N/A"


# --------------------------------------------------
# Calculate linked event information
# --------------------------------------------------

event_ids = {
    event_id
    for finding_event_ids in findings["event_ids"]
    for event_id in finding_event_ids
}

flow_ids = {
    flow_id
    for finding_flow_ids in findings["flow_ids"]
    for flow_id in finding_flow_ids
}

related_event_data = get_events_by_ids(sorted(event_ids))

if related_event_data.empty and flow_ids:
    related_event_data = get_events_by_flow_ids(sorted(flow_ids))

event_count = len(related_event_data)



# --------------------------------------------------
# Case summary
# --------------------------------------------------

summary_col1, summary_col2, summary_col3, summary_col4 = st.columns(4)

with summary_col1:
    st.markdown("**Source IP**")
    st.write(source_ip)

with summary_col2:
    st.markdown("**First Seen**")
    st.write(first_seen)

with summary_col3:
    st.markdown("**Last Seen**")
    st.write(last_seen)

with summary_col4:
    st.markdown("**Events**")
    st.write(event_count)


st.divider()


# --------------------------------------------------
# Related Events
# --------------------------------------------------

st.subheader("Related Events")

if not related_event_data.empty:

    # Format timestamps for display without changing database values.
    timestamps = (
        pd.to_datetime(
            related_event_data["ts"],
            utc=True,
            errors="coerce",
        )
        .dt.strftime("%Y-%m-%d %H:%M:%S UTC")
        .fillna("N/A")
    )

    related_events = pd.DataFrame({
        "Timestamp (UTC)": timestamps,
        "Event Type": related_event_data["event_type"],
        "Source IP": related_event_data["src_ip"].fillna("N/A"),
        "Source Port": related_event_data["src_port"].apply(
            lambda value: (
                str(int(value))
                if pd.notna(value)
                else "N/A"
            )
        ),
        "Destination IP": related_event_data["dest_ip"].fillna("N/A"),
        "Destination Port": related_event_data["dest_port"].apply(
            lambda value: (
                str(int(value))
                if pd.notna(value)
                else "N/A"
            )
        ),
        "Protocol": related_event_data["proto"].fillna("N/A"),
    })

    st.dataframe(
        related_events,
        width="stretch",
        hide_index=True,
    )

else:
    st.info(
        "No linked network events are available for this case. "
        "The associated findings may not contain event references."
    )

# --------------------------------------------------
# MITRE ATT&CK Mapping
# --------------------------------------------------

st.subheader("MITRE ATT&CK Mapping")

st.info(
    "No MITRE ATT&CK mapping is currently available."
)

# --------------------------------------------------
# Primary Evidence
# --------------------------------------------------

st.divider()

st.subheader("Primary Evidence")

if findings.empty:

    st.info(
        "No detection findings are available for this case."
    )

else:

    st.caption(
        "Evidence below comes from the detection findings and linked "
        "network events stored by the analysis pipeline."
    )

    for _, finding in findings.iterrows():

        rule_name = finding["rule_name"]
        finding_id = finding["finding_id"]
        finding_timestamp = finding["timestamp"]
        description = finding["description"]
        source_ip = finding["source_ip"]
        finding_priority = finding["priority"]

        with st.expander(
            f"{rule_name} — {finding_id}"
        ):
            st.markdown("**Detection rule**")
            st.write(rule_name)

            st.markdown("**Timestamp**")
            st.write(finding_timestamp or "N/A")

            st.markdown("**Source IP**")
            st.write(source_ip or "N/A")

            st.markdown("**Description**")
            st.write(description or "No description available.")

            st.markdown("**Finding priority**")
            st.write(
                finding_priority
                if pd.notna(finding_priority)
                else "N/A"
            )

            # Show the event IDs associated with this finding.
            finding_event_ids = finding["event_ids"]

            st.markdown("**Linked event IDs**")

            if finding_event_ids:
                st.write(", ".join(
                    str(event_id)
                    for event_id in finding_event_ids
                ))
            else:
                st.write("No event IDs linked to this finding.")

# --------------------------------------------------
# Notes
# --------------------------------------------------

st.divider()

st.subheader("Notes")

correlation_strength = case["correlation_strength"]

if correlation_strength == "Single":
    st.write(
        "This case contains a single detection finding. "
        "No additional findings were correlated with it."
    )

else:
    st.write(
        f"Correlation strength: **{correlation_strength}**."
    )

    if case["correlation_reasons"]:
        st.markdown("**Correlation Reasons**")

        for reason in case["correlation_reasons"]:
            st.write(f"- {reason}")


# --------------------------------------------------
# Footer
# --------------------------------------------------

st.divider()

st.caption(
    "Candidate cases are generated from automated detection and correlation. "
    "They require analyst validation and are not automatically confirmed attacks."
)
