import json

import streamlit as st
import pandas as pd

from data.analysis_data import get_case, get_case_findings


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

# The current analysis database stores detection findings
# separately from the raw EVE events.
# Therefore, the approved "Events" field is not populated
# with a fabricated value.
event_count = "Pending"


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

if not findings.empty:

    related_events = pd.DataFrame([
    {
        "Timestamp": finding["timestamp"],
        "Event Type": finding["rule_name"],
        "Destination": (
            ", ".join(
                json.loads(finding["details"]).get(
                    "destination_ips", []
                )
            )
            if finding["details"]
            else "N/A"
        ),
        "Details": finding["description"],
    }
    for _, finding in findings.iterrows()
    ])

    st.dataframe(
        related_events,
        width="stretch",
        hide_index=True
    )

else:
    st.info("No related events are available.")


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

st.info(
    "No primary evidence is currently available "
    "for this case."
)


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