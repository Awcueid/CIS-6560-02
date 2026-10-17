import streamlit as st

v0_page = st.Page("Legacy_Dashboard.py", title="Version 0.0 (before Oct 14)")
v1_page = st.Page("pages/0_SOC_Main.py", title="Version 1.0 (Development)")

if "selected_version" not in st.session_state:
    st.session_state.selected_version = None


if st.session_state.selected_version is None:

    st.set_page_config(page_title="Context-Aware Vulnerability Prioritization Engine Version Selector", layout="centered", initial_sidebar_state="collapsed")
    
    st.title("Context-Aware Vulnerability Prioritization Engine")   
    st.subheader("Version Selection")
    st.write("Select a system version to run. (V0.0: Streamlit Test | V1.0: In Development)")
    st.divider()

    col1, col2 = st.columns(2)
    with col1:
        st.subheader("Version 0.0")
        st.caption("for Streamlit testing")
        if st.button("Run Version 0.0", key="go_v0", use_container_width=True):
            st.session_state.selected_version = v0_page
            st.rerun()

    with col2:
        st.subheader("Version 1.0")
        st.caption("In Development")
        if st.button("Run Version 1.0", key="go_v1", type="primary", use_container_width=True):
            st.session_state.selected_version = v1_page
            st.rerun()

else:
    pg = st.navigation([st.session_state.selected_version], position="hidden")
    pg.run()
