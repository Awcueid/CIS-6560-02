import streamlit as st
from utils import apply_theme, render_sidebar

# Apply theme and render sidebar toggle
apply_theme()
render_sidebar()

st.title("Risk Weight Tuning Engine")

with st.container(border=True):
    st.subheader("Adjust Risk Calculation Weights (Total must equal 1.00)")
    
    w_severity = st.slider("Severity (CVSS)", 0.0, 1.0, float(st.session_state.weights["severity"]), 0.05, key="sev_slider")
    w_exploited = st.slider("Simulated Exploited in Wild", 0.0, 1.0, float(st.session_state.weights["exploited"]), 0.05, key="exp_slider")
    w_poc = st.slider("Simulated PoC Availability", 0.0, 1.0, float(st.session_state.weights["poc"]), 0.05, key="poc_slider")
    w_patch = st.slider("Patch Difficulty", 0.0, 1.0, float(st.session_state.weights["patch"]), 0.05, key="patch_slider")
    w_controls = st.slider("Compensating Controls", 0.0, 1.0, float(st.session_state.weights["controls"]), 0.05, key="ctrl_slider")
    w_asset = st.slider("Asset Criticality", 0.0, 1.0, float(st.session_state.weights["asset"]), 0.05, key="asset_slider")
    w_transfer = st.slider("Risk Acceptance / Transfer", 0.0, 1.0, float(st.session_state.weights["transfer"]), 0.05, key="trans_slider")

    total_weight = round(w_severity + w_exploited + w_poc + w_patch + w_controls + w_asset + w_transfer, 2)
    
    if total_weight == 1.00:
        st.success(f"Weights verified: total = {total_weight:.2f}")
        st.session_state.weights = {
            "severity": w_severity,
            "exploited": w_exploited,
            "poc": w_poc,
            "patch": w_patch,
            "controls": w_controls,
            "asset": w_asset,
            "transfer": w_transfer
        }
    else:
        st.error(f"Weights invalid: must equal 1.00 (current total: {total_weight:.2f})")