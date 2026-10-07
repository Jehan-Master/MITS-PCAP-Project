import streamlit as st
import pandas as pd

from data.analysis_data import get_cases


# --------------------------------------------------
# Page title
# --------------------------------------------------

st.title("Cases")
st.write(
    "Overview of all cases identified by the threat analysis system."
)


# --------------------------------------------------
# Case table data
# --------------------------------------------------

cases = get_cases()

case_table = pd.DataFrame([
    {
        "ID": case["case_id"],
        "Type": "Pending",
        "Source IP": ", ".join(case["source_ips"])
        if case["source_ips"]
        else "N/A",
        "Priority": "Pending",
        "Status": "Pending"
    }
    for _, case in cases.iterrows()
])


# --------------------------------------------------
# Filters
# --------------------------------------------------

st.subheader("Filter Cases")

col1, col2, col3 = st.columns(3)

with col1:
    priority_filter = st.selectbox(
        "Priority",
        ["All", "Pending"]
    )

with col2:
    status_filter = st.selectbox(
        "Status",
        ["All", "Pending"]
    )

with col3:
    type_filter = st.selectbox(
        "Type",
        ["All", "Pending"]
    )


# --------------------------------------------------
# Apply filters
# --------------------------------------------------

filtered_cases = case_table.copy()

if priority_filter != "All":
    filtered_cases = filtered_cases[
        filtered_cases["Priority"] == priority_filter
    ]

if status_filter != "All":
    filtered_cases = filtered_cases[
        filtered_cases["Status"] == status_filter
    ]

if type_filter != "All":
    filtered_cases = filtered_cases[
        filtered_cases["Type"] == type_filter
    ]


# --------------------------------------------------
# Display cases
# --------------------------------------------------

st.subheader("All Cases")

if filtered_cases.empty:

    st.info("No cases match the selected filters.")

else:

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
    for _, case in filtered_cases.iterrows():

        col1, col2, col3, col4, col5 = st.columns(
            [1, 2, 2, 1, 1]
        )

        with col1:

            if st.button(
                case["ID"],
                key=f"case_{case['ID']}",
                type="tertiary"
            ):
                st.session_state["selected_case"] = case["ID"]
                st.switch_page("pages/case_detail.py")

        col2.write(case["Type"])
        col3.write(case["Source IP"])
        col4.write(case["Priority"])
        col5.write(case["Status"])


# --------------------------------------------------
# Footer
# --------------------------------------------------

st.divider()

st.caption(
    "Candidate cases are generated from automated detection and correlation. "
    "They require analyst validation and are not automatically confirmed attacks."
)