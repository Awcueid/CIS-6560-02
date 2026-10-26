import os
import pandas as pd
import streamlit as st

EXCEL_FILE_PATH = "reference_data/vulnerability_contextualization_scanner_sample_updated.xlsx"

if st.session_state.get("df_sample_excel") is None and os.path.exists(EXCEL_FILE_PATH):
    try:
        st.session_state.df_sample_excel = pd.read_excel(EXCEL_FILE_PATH)
    except Exception as e:
        st.error(f"Error reading sample excel dataset: {e}")

st.title("Sample Dataset")

if st.session_state.df_sample_excel is not None:
    with st.container(border=True):
        st.dataframe(st.session_state.df_sample_excel, use_container_width=True, hide_index=True)
else:
    st.warning(f"Sample dataset not found at path: {EXCEL_FILE_PATH}")