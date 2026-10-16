import os
import streamlit as st
from utils import apply_theme, render_sidebar

# Apply theme and render sidebar toggle
apply_theme()
render_sidebar()

REPORTS_DIR = "scan_reports"
API_KEY = os.getenv("NVD_API_KEY", "")

st.title("System Configuration")
st.write(f"**Target Scan Directory Route:** `{REPORTS_DIR}/`")
st.write(f"**NVD Authorized Token Active:** `{'Yes (Key Detected)' if API_KEY else 'No (Anonymized Request Constraints Apply)'}`")