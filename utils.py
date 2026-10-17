import streamlit as st


MENU_OPTIONS = [
    "Single Pane of Glass"
    "Sample Dataset",
    "NVD API Search Query"
]


def render_sidebar_menu():
    """Render the unified sidebar navigation menu and return the selected module."""

    st.sidebar.subheader("Navigation Menu")
    st.sidebar.markdown("---")

    selected_module = st.sidebar.radio(
        "Select Module",
        MENU_OPTIONS,
        label_visibility="collapsed"
    )

    return selected_module