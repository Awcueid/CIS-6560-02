import streamlit as st

def apply_theme():
    """ Applies dynamic dark/light theme styling across all pages consistently """
    if "dark_mode" not in st.session_state:
        st.session_state.dark_mode = False

    bg_color = "#0E1117" if st.session_state.dark_mode else "#F8F9FA"
    text_color = "#FAFAFA" if st.session_state.dark_mode else "#1E293B"
    sidebar_bg = "#161B22" if st.session_state.dark_mode else "#FFFFFF"
    sidebar_text = "#FAFAFA" if st.session_state.dark_mode else "#1E293B"
    border_color = "#30363D" if st.session_state.dark_mode else "#E2E8F0"

    st.markdown(f"""
    <style>
        /* Main application background and text color */
        .stApp {{
            background-color: {bg_color};
            color: {text_color};
        }}
        .block-container {{
            padding-top: 1.5rem;
            padding-bottom: 1rem;
            max-width: 100%;
        }}
        h1, h3, p, span, label {{
            color: {text_color} !important;
        }}

        /* Sidebar background and text synchronization */
        section[data-testid="stSidebar"] {{
            background-color: {sidebar_bg};
            border-right: 1px solid {border_color};
        }}
        section[data-testid="stSidebar"] h1, 
        section[data-testid="stSidebar"] h2, 
        section[data-testid="stSidebar"] h3, 
        section[data-testid="stSidebar"] span, 
        section[data-testid="stSidebar"] label, 
        section[data-testid="stSidebar"] p {{
            color: {sidebar_text} !important;
        }}
    </style>
    """, unsafe_allow_html=True)

def render_sidebar():
    """ Renders the common sidebar toggle and navigation title on every page """
    st.sidebar.title("Operations Hub")
    is_dark = st.sidebar.toggle("Dark Mode", value=st.session_state.dark_mode)

    if is_dark != st.session_state.dark_mode:
        st.session_state.dark_mode = is_dark
        st.rerun()

    st.sidebar.markdown("---")
    st.sidebar.caption("Scoring Engine v1.1.2")