import streamlit as st


def apply_theme():
    st.markdown(
        """
        <style>
            .block-container {
                padding-top: 2rem;
                padding-bottom: 2rem;
            }

            h1, h2, h3 {
                color: #0F4C81;
            }
        </style>
        """,
        unsafe_allow_html=True,
    )


def render_sidebar():
    """Render the shared application sidebar."""
    with st.sidebar:
        st.title("CAVPE")
        st.caption("Cybersecurity Risk Assessment Platform")
        st.divider()