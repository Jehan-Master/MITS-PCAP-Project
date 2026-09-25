import streamlit as st
import pandas as pd

from data.fake_cases import FAKE_CASES


# --------------------------------------------------
# Find the selected case
# --------------------------------------------------

selected_case_id = st.session_state.get("selected_case")

if not selected_case_id:
    st.warning("No case has been selected.")

    if st.button("← Cases"):
        st.switch_page("pages/cases.py")

    st.stop()


selected_case = next(
    (
        case
        for case in FAKE_CASES
        if case["id"] == selected_case_id
    ),
    None
)

if selected_case is None:
    st.error("The selected case could not be found.")

    if st.button("← Cases"):
        st.switch_page("pages/cases.py")

    st.stop()


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
            {selected_case["id"]}
        </div>
        """,
        unsafe_allow_html=True
    )


# --------------------------------------------------
# Case header
# --------------------------------------------------

header_col1, header_col2 = st.columns([3, 1])

with header_col1:
    st.title(selected_case["type"])

with header_col2:
    priority = selected_case["priority"]

    st.markdown(
        f"""
        <div style="
            text-align: right;
            font-size: 1.1rem;
            font-weight: 700;
            padding-top: 1.2rem;
        ">
            {priority.upper()}
        </div>
        """,
        unsafe_allow_html=True
    )


# --------------------------------------------------
# Calculate case summary information
# --------------------------------------------------

events = selected_case.get("events", [])

timestamps = [
    event["timestamp"]
    for event in events
    if event.get("timestamp")
]

if timestamps:
    first_seen = min(timestamps)
    last_seen = max(timestamps)
else:
    first_seen = "N/A"
    last_seen = "N/A"

event_count = len(events)

source_ip = selected_case.get(
    "source_ip",
    "N/A"
)


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

if events:
    related_events = pd.DataFrame([
        {
            "Timestamp": event.get(
                "timestamp",
                "N/A"
            ),
            "Event Type": event.get(
                "type",
                "N/A"
            ),
            "Destination": (
                f'{event.get("destination_ip", "N/A")}:'
                f'{event.get("destination_port", "N/A")}'
            ),
            "Details": (
                "Failed"
                if "Failed" in event.get("type", "")
                else "Detected"
            )
        }
        for event in events
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

mapping = selected_case.get(
    "attack_mapping"
)

if mapping:
    attack_mapping = pd.DataFrame([
        {
            "Tactic / Technique": (
                f'{mapping.get("tactic", "N/A")}\n'
                f'{mapping.get("technique_id", "N/A")} - '
                f'{mapping.get("technique", "N/A")}'
            ),
            "Confidence": mapping.get(
                "confidence",
                "N/A"
            ),
            "Evidence": (
                "Yes"
                if selected_case.get("evidence")
                else "No"
            )
        }
    ])

    st.dataframe(
        attack_mapping,
        width="stretch",
        hide_index=True
    )

    st.markdown("**Mapping Status**")

    st.write(
        mapping.get(
            "status",
            "N/A"
        )
    )

    st.markdown("**Reason**")

    st.write(
        mapping.get(
            "reason",
            "No explanation available."
        )
    )

else:
    st.info(
        "No MITRE ATT&CK mapping is currently available."
    )


# --------------------------------------------------
# Primary Evidence
# --------------------------------------------------

st.divider()

st.subheader("Primary Evidence")

evidence = selected_case.get("evidence")

if evidence:

    # Get the first event as the primary event.
    primary_event = events[0] if events else {}

    source_ip = primary_event.get(
        "source_ip",
        "N/A"
    )

    source = evidence.get(
        "source",
        ""
    )

    # Extract source port from the full source endpoint.
    source_port = "N/A"

    if ":" in source:
        source_port = source.rsplit(":", 1)[1]

    destination_ip = primary_event.get(
        "destination_ip",
        "N/A"
    )

    destination_port = primary_event.get(
        "destination_port",
        "N/A"
    )

    evidence_fields = [
        ("EVE ID", "eve_id", evidence.get("eve_id", "N/A")),
        ("PCAP File", "pcap_file", evidence.get("pcap_file", "N/A")),
        (
            "Packet Reference",
            "packet_reference",
            evidence.get("packet_reference", "N/A")
        ),
        (
            "Timestamp",
            "timestamp",
            evidence.get("timestamp", "N/A")
        ),
        ("Source IP", "source_ip", source_ip),
        ("Source Port", "source_port", source_port),
        (
            "Destination IP",
            "destination_ip",
            destination_ip
        ),
        (
            "Destination Port",
            "destination_port",
            destination_port
        ),
        ("Protocol", "protocol", evidence.get("protocol", "N/A"))
    ]

    for field_name, field_key, value in evidence_fields:

        field_col, value_col = st.columns([1, 2])

        with field_col:
            st.markdown(f"**{field_name}**")

        with value_col:

            if value != "N/A":

                if st.button(
                    str(value),
                    key=(
                        f"evidence_"
                        f"{selected_case['id']}_"
                        f"{field_key}"
                    ),
                    type="tertiary"
                ):

                    st.session_state[
                        "evidence_search"
                    ] = str(value)

                    st.session_state[
                        "evidence_page"
                    ] = 1

                    st.switch_page(
                        "pages/evidence.py"
                    )

            else:
                st.write("N/A")

else:
    st.info(
        "No primary evidence is currently available "
        "for this case."
    )

# --------------------------------------------------
# Notes
# --------------------------------------------------

st.divider()

st.subheader("Notes")

st.write(
    selected_case.get(
        "description",
        "No notes are available for this case."
    )
)

# --------------------------------------------------
# Footer
# --------------------------------------------------

st.divider()

st.caption(
    "Prototype dashboard — metrics and case data currently use example values."
)