import streamlit as st


# --------------------------------------------------
# Pages
# --------------------------------------------------

overview = st.Page(
    "pages/overview.py",
    title="Overview",
    icon=":material/dashboard:"
)

cases = st.Page(
    "pages/cases.py",
    title="Cases",
    icon=":material/search:"
)

case_detail = st.Page(
    "pages/case_detail.py",
    title="Case Detail",
    icon=":material/description:",
    visibility="hidden"
)

timeline = st.Page(
    "pages/timeline.py",
    title="Timeline",
    icon=":material/timeline:"
)

evidence = st.Page(
    "pages/evidence.py",
    title="Evidence",
    icon=":material/article:"
)


# --------------------------------------------------
# Navigation
# --------------------------------------------------

pg = st.navigation(
    [
        overview,
        cases,
        case_detail,
        timeline,
        evidence
    ],
    position="sidebar"
)


# --------------------------------------------------
# Run selected page
# --------------------------------------------------

pg.run()