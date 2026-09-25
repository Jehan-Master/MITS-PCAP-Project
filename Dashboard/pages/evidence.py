import streamlit as st
import pandas as pd

from data.fake_cases import FAKE_CASES


# --------------------------------------------------
# Page title
# --------------------------------------------------

st.title("Evidence")


# --------------------------------------------------
# Prepare evidence data
# --------------------------------------------------

evidence_rows = []

for case in FAKE_CASES:
    case_evidence = case.get("evidence", {})

    for event in case.get("events", []):
        source = case_evidence.get("source", "")
        source_port = "N/A"

        if ":" in source:
            source_port = source.rsplit(":", 1)[1]

        evidence_rows.append({
            "Timestamp": event.get("timestamp", "N/A"),
            "Source IP": event.get("source_ip", "N/A"),
            "Source Port": source_port,
            "Destination IP": event.get("destination_ip", "N/A"),
            "Destination Port": event.get("destination_port", "N/A"),
            "Protocol": event.get("protocol", "N/A"),
            "Info": event.get("type", "N/A"),
            "Case ID": case.get("id", "N/A"),
            "Evidence ID": event.get("evidence", "N/A"),
            "PCAP File": case_evidence.get("pcap_file", "N/A"),
            "Packet Reference": case_evidence.get("packet_reference", "N/A")
        })


if not evidence_rows:
    st.info("No evidence is currently available.")
    st.stop()


evidence_df = pd.DataFrame(evidence_rows)

evidence_df["Timestamp"] = pd.to_datetime(
    evidence_df["Timestamp"]
)

evidence_df = evidence_df.sort_values(
    "Timestamp"
)


# --------------------------------------------------
# Search and filter
# --------------------------------------------------

search_col, filter_col = st.columns(
    [5, 1]
)

with search_col:

    search_query = st.session_state.pop(
        "evidence_search",
        ""
    )

    search_query = st.text_input(
        "Search",
        value=search_query,
        placeholder="Search by IP, event type, EVE ID, PCAP file, etc...",
        label_visibility="collapsed",
        key="evidence_search_input"
    )

with filter_col:
    filter_option = st.selectbox(
        "Filter",
        [
            "All",
            "TCP",
            "UDP"
        ],
        label_visibility="collapsed"
    )


filtered_evidence = evidence_df.copy()


# Search through several useful fields
if search_query:
    search_query = search_query.lower()

    search_mask = (
        filtered_evidence["Source IP"]
        .astype(str)
        .str.lower()
        .str.contains(search_query, na=False)

        |

        filtered_evidence["Source Port"]
        .astype(str)
        .str.lower()
        .str.contains(search_query, na=False)

        |

        filtered_evidence["Destination IP"]
        .astype(str)
        .str.lower()
        .str.contains(search_query, na=False)

        |

        filtered_evidence["Destination Port"]
        .astype(str)
        .str.lower()
        .str.contains(search_query, na=False)

        |

        filtered_evidence["Protocol"]
        .astype(str)
        .str.lower()
        .str.contains(search_query, na=False)

        |

        filtered_evidence["Info"]
        .astype(str)
        .str.lower()
        .str.contains(search_query, na=False)

        |

        filtered_evidence["Evidence ID"]
        .astype(str)
        .str.lower()
        .str.contains(search_query, na=False)

        |

        filtered_evidence["Case ID"]
        .astype(str)
        .str.lower()
        .str.contains(search_query, na=False)

        |

        filtered_evidence["PCAP File"]
        .astype(str)
        .str.lower()
        .str.contains(search_query, na=False)

        |

        filtered_evidence["Packet Reference"]
        .astype(str)
        .str.lower()
        .str.contains(search_query, na=False)

        |

        filtered_evidence["Timestamp"]
        .astype(str)
        .str.lower()
        .str.contains(search_query, na=False)
    )

    filtered_evidence = filtered_evidence[
        search_mask
    ]

# Protocol filter
if filter_option != "All":
    filtered_evidence = filtered_evidence[
        filtered_evidence["Protocol"] == filter_option
    ]

# --------------------------------------------------
# Pagination
# --------------------------------------------------

rows_per_page = 5

total_rows = len(filtered_evidence)

if total_rows > 0:
    total_pages = (
        (total_rows - 1) // rows_per_page
    ) + 1
else:
    total_pages = 1

if "evidence_page" not in st.session_state:
    st.session_state["evidence_page"] = 1

current_page = st.session_state["evidence_page"]

if current_page > total_pages:
    current_page = total_pages
    st.session_state["evidence_page"] = current_page

start_index = (
    current_page - 1
) * rows_per_page

end_index = start_index + rows_per_page

page_evidence = filtered_evidence.iloc[
    start_index:end_index
]


# --------------------------------------------------
# Evidence tabs
# --------------------------------------------------

pcap_tab, eve_tab, suricata_tab = st.tabs(
    [
        "PCAP",
        "EVE-JSON",
        "Suricata Alerts"
    ]
)


# --------------------------------------------------
# PCAP tab
# --------------------------------------------------

with pcap_tab:

    st.subheader("PCAP Evidence")

    if filtered_evidence.empty:
        st.info(
            "No PCAP evidence matches the current filters."
        )

    else:
        display_df = page_evidence.copy()

        display_df["Timestamp"] = (
            display_df["Timestamp"]
            .dt.strftime("%Y-%m-%d %H:%M:%S")
        )

        display_df = display_df[
            [
                "Timestamp",
                "Source IP",
                "Source Port",
                "Destination IP",
                "Destination Port",
                "Protocol",
                "Info"
            ]
        ]

        st.dataframe(
            display_df,
            width="stretch",
            hide_index=True
        )


# --------------------------------------------------
# EVE-JSON tab
# --------------------------------------------------

with eve_tab:

    st.subheader("EVE-JSON Evidence")

    if filtered_evidence.empty:
        st.info(
            "No EVE-JSON evidence matches the current filters."
        )

    else:
        eve_display_df = page_evidence.copy()

        eve_display_df["Timestamp"] = (
            eve_display_df["Timestamp"]
            .dt.strftime("%Y-%m-%d %H:%M:%S")
        )

        eve_display_df = eve_display_df[
            [
                "Timestamp",
                "Evidence ID",
                "Source IP",
                "Source Port",
                "Destination IP",
                "Destination Port",
                "Protocol",
                "Info"
            ]
        ]

        st.dataframe(
            eve_display_df,
            width="stretch",
            hide_index=True
        )


# --------------------------------------------------
# Suricata Alerts tab
# --------------------------------------------------

with suricata_tab:

    st.subheader("Suricata Alerts")

    # For now, create representative alert data
    # from the fake suspicious events.
    alert_rows = []

    for _, row in filtered_evidence.iterrows():
        alert_rows.append(
            {
                "Timestamp": row["Timestamp"],
                "Alert": row["Info"],
                "Source IP": row["Source IP"],
                "Destination IP": row["Destination IP"],
                "Protocol": row["Protocol"]
            }
        )

    alert_df = pd.DataFrame(alert_rows)

    if alert_df.empty:
        st.info(
            "No Suricata alerts match the current filters."
        )

    else:
        alert_df["Timestamp"] = (
            alert_df["Timestamp"]
            .dt.strftime("%Y-%m-%d %H:%M:%S")
        )

        st.dataframe(
            alert_df,
            width="stretch",
            hide_index=True
        )


# --------------------------------------------------
# Pagination controls
# --------------------------------------------------

if total_rows > 0:

    page_col1, page_col2, page_col3 = st.columns(
        [1, 3, 1]
    )

    with page_col1:
        if current_page > 1:
            if st.button(
                "‹",
                key="previous_page"
            ):
                st.session_state["evidence_page"] -= 1
                st.rerun()

    with page_col2:
        st.markdown(
            f"""
            <div style="
                text-align: center;
                padding-top: 0.4rem;
            ">
                Page {current_page} of {total_pages}
            </div>
            """,
            unsafe_allow_html=True
        )

    with page_col3:
        if current_page < total_pages:
            if st.button(
                "›",
                key="next_page"
            ):
                st.session_state["evidence_page"] += 1
                st.rerun()

# --------------------------------------------------
# PCAP information
# --------------------------------------------------

st.divider()

info_col1, info_col2 = st.columns(
    [4, 1]
)

with info_col1:
    st.info(
        "View the original PCAP file for full packet details."
    )

with info_col2:
    if st.button(
        "Open in Wireshark",
        key="open_wireshark"
    ):
        st.info(
            "Wireshark integration will be connected "
            "when the real PCAP files are available."
        )


# --------------------------------------------------
# Prototype notice
# --------------------------------------------------

st.caption(
    "Prototype dashboard — evidence currently represents "
    "example values derived from the fake case dataset."
)