import json
import os
import subprocess
import sys
import numpy as np
import pandas as pd
import plotly.express as px
import streamlit as st

# 1. Page Configuration
st.set_page_config(page_title="SOC Main", layout="wide")

# Force light theme mode regardless of system or browser dark mode settings
st.markdown(
    """
    <style>
    :root {
        --color-background: #ffffff;
        --color-text: #31333F;
    }
    </style>
    """,
    unsafe_allow_html=True
)

# 2. Native Multipage Directory Scanning Enforcer
# This explicit declaration prevents the left sidebar menu from disappearing due to numeric file naming layout conflicts
with st.sidebar:
    st.markdown("### Navigation Controls")
    st.markdown("---")

S_DIR = os.path.dirname(os.path.abspath(__file__))
P_DIR = os.path.dirname(S_DIR)

# Synced path to look inside the 'engines' subfolder for absolute consistency
W_CONF = os.path.join(P_DIR, "engines", "weight_config.json")
TAX_FILES = {k: os.path.join(S_DIR, f"taxonomy_option_{k.lower()}.json") for k in ["A", "B", "C"]}
SCORING_SCRIPT_PATH = os.path.join(P_DIR, "engines", "scoring.py")
OUTPUT_EXCEL_PATH = os.path.join(S_DIR, "multi_taxonomy_weighted_risk_model.xlsx")

# 3. Mathematical Risk Engine
def get_matrix_config(opt_letter):
    w, m = {}, {}
    if os.path.exists(W_CONF):
        try: w = json.load(open(W_CONF, "r", encoding="utf-8")).get("weights", {})
        except: pass
    t_path = TAX_FILES.get(opt_letter, "")
    if os.path.exists(t_path):
        try: m = {str(k).strip().lower(): v for k, v in json.load(open(t_path, "r", encoding="utf-8")).get("exposure_classification_mapping", {}).items()}
        except: pass
    return w, m

def calc_risk(row, asset_val, w):
    v_sev = (row["CVSS base score"] / 10.0) if pd.notna(row.get("CVSS base score")) else 0.0
    v_exp = 1.0 if "active" in str(row.get("Exploitation context", "")).lower() else 0.0
    return round(((v_sev * w.get("severity", 0.4)) + (v_exp * w.get("exploited_in_the_wild", 0.15)) + 
                  (0.5 * w.get("poc_exploit_availability", 0.1)) + (0.5 * w.get("patch_difficulty", 0.1)) + 
                  (0.3 * w.get("compensating_controls", 0.1)) + ((asset_val / 4.0) * w.get("asset_criticality", 0.1))) * 100.0, 2)

# 4. Data Ingestion
@st.cache_data
def load_data():
    p1, p2 = os.path.join("reference_data", "vulnerability_cisa_kev_enriched.xlsx"), "vulnerability_contextualization_scanner_sample_updated.xlsx"
    if not os.path.exists(p1) and os.path.exists(os.path.join(P_DIR, "reference_data", p2)): p2 = os.path.join(P_DIR, "reference_data", p2)
    tgt = p1 if os.path.exists(p1) else (p2 if os.path.exists(p2) else None)
    if not tgt: return pd.DataFrame()
    df = pd.read_excel(tgt, engine="openpyxl") if tgt.endswith(".xlsx") else pd.read_csv(tgt)
    if "CISA KEV Status" not in df.columns:
        df["CISA KEV Status"] = np.where(df.get("Exploitation context", "").astype(str).str.lower().str.contains("known exploited"), "Confirmed - Active Exploitation", "Standard Monitored")
    return df[df["Finding ID"].astype(str).str.startswith("VULN-", na=False)].head(300)

# Load compiled model from scoring.py if available
def load_compiled_model_data():
    if os.path.exists(OUTPUT_EXCEL_PATH):
        try:
            return pd.read_excel(OUTPUT_EXCEL_PATH, engine="openpyxl")
        except:
            return None
    return None

if "active_taxonomy" not in st.session_state: st.session_state.active_taxonomy = "Option B"


# 5. Main Dashboard Header View Layout
st.title("SOC Main Dashboard")

# System Control Room Section to execute the backend script
st.subheader("Backend Engine Control Room")
if st.button("Execute Scoring Engine (scoring.py)", use_container_width=True, type="primary"):
    if os.path.exists(SCORING_SCRIPT_PATH):
        with st.spinner("Executing background mathematical calculations via scoring.py..."):
            try:
                result = subprocess.run(
                    [sys.executable, SCORING_SCRIPT_PATH],
                    capture_output=True, text=True, check=True
                )
                st.success("Scoring Engine compiled and completed successfully.")
                st.cache_data.clear()
                st.rerun()
            except subprocess.CalledProcessError as e:
                st.error(f"Execution Error inside scoring.py script pipeline: {e.stderr}")
            except Exception as ex:
                st.error(f"Unexpected operational error during subsystem routing: {ex}")
    else:
        st.error(f"Target executable background script not found at absolute path destination: {SCORING_SCRIPT_PATH}")

st.markdown("---")

st.subheader("Select Active Taxonomy Perspective")
btn_none, btn_a, btn_b, btn_c = st.columns(4)

with btn_none:
    if st.button("None", use_container_width=True, type="secondary" if st.session_state.active_taxonomy != "None" else "primary"):
        st.session_state.active_taxonomy = "None"
        st.rerun()
with btn_a:
    if st.button("Option A", use_container_width=True, type="secondary" if st.session_state.active_taxonomy != "Option A" else "primary"):
        st.session_state.active_taxonomy = "Option A"
        st.rerun()
with btn_b:
    if st.button("Option B", use_container_width=True, type="secondary" if st.session_state.active_taxonomy != "Option B" else "primary"):
        st.session_state.active_taxonomy = "Option B"
        st.rerun()
with btn_c:
    if st.button("Option C", use_container_width=True, type="secondary" if st.session_state.active_taxonomy != "Option C" else "primary"):
        st.session_state.active_taxonomy = "Option C"
        st.rerun()

st.markdown(f"**Current Active View:** Framework processing routed to **{st.session_state.active_taxonomy}**")
st.markdown("---")

# 6. Engine Processing
v_data = load_data()
is_dyn = not v_data.empty and "Exposure classification" in v_data.columns and st.session_state.active_taxonomy != "None"

if is_dyn:
    w_mat, tax_map = get_matrix_config(st.session_state.active_taxonomy[-1])
    a_scores = v_data["Exposure classification"].astype(str).str.strip().str.lower().map(tax_map).fillna(1).astype(int)
    v_data["Normalized Score"] = v_data.apply(lambda r: calc_risk(r, a_scores.loc[r.name], w_mat), axis=1)

# 7. UI Metrics & Charts
tot = len(v_data)
s_col = "Normalized Score" if is_dyn else "CVSS base score"
h_thresh = 75.0 if is_dyn else 8.0

# Calculate Contextual Priority metrics dynamically based on configuration threshold rules
if is_dyn:
    priority_count = len(v_data[v_data["Normalized Score"] >= 85.0]) if tot > 0 else 0
    priority_label = "Contextual Priority (Score >= 85)"
else:
    priority_count = len(v_data[v_data["CVSS base score"] >= 9.0]) if tot > 0 else 0
    priority_label = "Contextual Priority (CVSS >= 9.0)"

c1, c2, c3 = st.columns(3)
c1.metric("Total Active Detections", f"{tot:,}")
c2.metric(priority_label, f"{priority_count:,}")
c3.metric(f"High Risk Threshold (>= {h_thresh})", len(v_data[v_data[s_col] >= h_thresh]) if tot > 0 else 0)

ch_col, act_col = st.columns(2)
with ch_col:
    if tot > 0 and "Asset group" in v_data.columns:
        st.plotly_chart(px.pie(v_data["Asset group"].value_counts().reset_index(name="Count"), values="Count", names="Asset group", hole=0.4, title="Detections by Asset Group"), use_container_width=True)
with act_col:
    st.markdown("**Actionable Mitigation Directives (Top 5 Prioritized):**")
    
    compiled_df = load_compiled_model_data()
    
    if compiled_df is not None and not compiled_df.empty:
        if st.session_state.active_taxonomy == "Option A":
            model_sort_col = "Final_Risk_Score_Option_A"
        elif st.session_state.active_taxonomy == "Option C":
            model_sort_col = "Final_Risk_Score_Option_C"
        else:
            model_sort_col = "Final_Risk_Score_Option_B"
            
        if model_sort_col in compiled_df.columns:
            for _, r in compiled_df.sort_values(by=model_sort_col, ascending=False).head(5).iterrows():
                st.info(f"{str(r.get('CVE ID', 'No CVE'))} [{r.get('Asset group', 'General')}]: {r.get('Vulnerability title', 'Untitled Finding')} (Engine Score: {r.get(model_sort_col)})")
        else:
            if tot > 0:
                for _, r in v_data.sort_values(by=s_col, ascending=False).head(5).iterrows():
                    st.info(f"{str(r.get('CVE ID', 'No CVE'))} [{r.get('Asset group', 'General')}]: {r.get('Vulnerability title', 'Untitled Finding')} (Score: {r.get(s_col)})")
    else:
        if tot > 0:
            for _, r in v_data.sort_values(by=s_col, ascending=False).head(5).iterrows():
                st.info(f"{str(r.get('CVE ID', 'No CVE'))} [{r.get('Asset group', 'General')}]: {r.get('Vulnerability title', 'Untitled Finding')} (Score: {r.get(s_col)})")

# 8. Matrix Queues
def render_q(df):
    if df.empty: return st.warning("No tracking items found inside current queue perspective.")
    df_d = df.copy()
    df_d.insert(0, "No.", np.arange(1, len(df_d) + 1))
    cols = [c for c in ["No.", "Vulnerability title", "CVE ID", "CISA KEV Status", "Normalized Score", "CVSS base score"] if c in df_d.columns]
    st.dataframe(df_d[cols + [c for c in df_d.columns if c not in cols and c not in ["Finding ID", "Data status"]]], use_container_width=True, height=400, hide_index=True)

st.subheader("Strategic Model Comparison Matrix")
t1, t2, t3 = st.tabs(["Active Framework Queue", "CISA KEV Feed Validation", "All Discovered Vulnerabilities"])
with t1: render_q(v_data.sort_values(by=s_col, ascending=False) if tot > 0 else v_data)
with t2: render_q(v_data[v_data["CISA KEV Status"] == "Confirmed - Active Exploitation"] if "CISA KEV Status" in v_data.columns else pd.DataFrame())
with t3: render_q(v_data)
