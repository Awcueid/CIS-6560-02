import os
import streamlit as st
from dotenv import load_dotenv
from utils import apply_theme, render_sidebar

# ==========================================
# 1. INITIALIZATION & CORE SETTINGS
# ==========================================
load_dotenv()

API_KEY = os.getenv("NVD_API_KEY")
BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
REPORTS_DIR = "scan_reports"
CSV_FILE_PATH = "reference_data/Inventory_Lists.csv"
EXCEL_FILE_PATH = "reference_data/vulnerability_contextualization_scanner_sample_updated.xlsx"

st.set_page_config(
    page_title="SOC Dashboard - CIS6560 Sec02 - Context-Aware Vulnerability Prioritization",
    layout="wide"
)

# Apply global dynamic theme
apply_theme()

# ==========================================
# 2. GLOBAL SESSION STATE MANAGEMENT
# ==========================================
if "nvd_data" not in st.session_state:
    st.session_state.nvd_data = None
if "has_fetched" not in st.session_state:
    st.session_state.has_fetched = False
if "df_assets" not in st.session_state:
    st.session_state.df_assets = None
if "df_sample_excel" not in st.session_state:
    st.session_state.df_sample_excel = None
if "df_pipeline_results" not in st.session_state:
    st.session_state.df_pipeline_results = None

# Initialize global risk calculation weights
if "weights" not in st.session_state:
    st.session_state.weights = {
        "severity": 0.40,
        "exploited": 0.15,
        "poc": 0.10,
        "patch": 0.10,
        "controls": 0.10,
        "asset": 0.10,
        "transfer": 0.05
    }

# Render common sidebar navigation and theme toggle
render_sidebar()

# Main Hub Screen
st.title("SOC Dashboard Hub")
st.markdown("Select a module from the sidebar navigation to begin analysis.")