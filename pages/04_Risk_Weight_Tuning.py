import streamlit as st
from utils import apply_theme, render_sidebar

# Apply shared theme and sidebar
apply_theme()
render_sidebar()

# Initialize default weights only if they do not already exist
if "weights" not in st.session_state:
    st.session_state.weights = {
        "severity": 0.25,
        "exploited": 0.15,
        "poc": 0.10,
        "patch": 0.15,
        "controls": 0.10,
        "asset": 0.15,
        "transfer": 0.10,
    }

st.title("Risk Weight Tuning Engine")
st.caption(
    "Adjust the relative importance of each risk factor. "
    "The total of all weights must equal 1.00."
)

with st.container(border=True):
    st.subheader("Adjust Risk Calculation Weights")
    st.write("Total must equal **1.00**.")

    w_severity = st.slider(
        "Severity (CVSS)",
        min_value=0.0,
        max_value=1.0,
        value=float(st.session_state.weights["severity"]),
        step=0.05,
        key="sev_slider",
    )

    w_exploited = st.slider(
        "Simulated Exploited in Wild",
        min_value=0.0,
        max_value=1.0,
        value=float(st.session_state.weights["exploited"]),
        step=0.05,
        key="exp_slider",
    )

    w_poc = st.slider(
        "Simulated PoC Availability",
        min_value=0.0,
        max_value=1.0,
        value=float(st.session_state.weights["poc"]),
        step=0.05,
        key="poc_slider",
    )

    w_patch = st.slider(
        "Patch Difficulty",
        min_value=0.0,
        max_value=1.0,
        value=float(st.session_state.weights["patch"]),
        step=0.05,
        key="patch_slider",
    )

    w_controls = st.slider(
        "Compensating Controls",
        min_value=0.0,
        max_value=1.0,
        value=float(st.session_state.weights["controls"]),
        step=0.05,
        key="ctrl_slider",
    )

    w_asset = st.slider(
        "Asset Criticality",
        min_value=0.0,
        max_value=1.0,
        value=float(st.session_state.weights["asset"]),
        step=0.05,
        key="asset_slider",
    )

    w_transfer = st.slider(
        "Risk Acceptance / Transfer",
        min_value=0.0,
        max_value=1.0,
        value=float(st.session_state.weights["transfer"]),
        step=0.05,
        key="trans_slider",
    )

    total_weight = round(
        w_severity
        + w_exploited
        + w_poc
        + w_patch
        + w_controls
        + w_asset
        + w_transfer,
        2,
    )

    st.metric("Total Weight", f"{total_weight:.2f}")

    if abs(total_weight - 1.00) < 0.001:
        st.success(f"Weights verified: total = {total_weight:.2f}")

        st.session_state.weights = {
            "severity": w_severity,
            "exploited": w_exploited,
            "poc": w_poc,
            "patch": w_patch,
            "controls": w_controls,
            "asset": w_asset,
            "transfer": w_transfer,
        }

        st.json(st.session_state.weights)

    else:
        st.error(
            f"Weights invalid: must equal 1.00 "
            f"(current total: {total_weight:.2f})"
        )

        difference = round(1.00 - total_weight, 2)

        if difference > 0:
            st.info(f"Add **{difference:.2f}** more total weight.")
        else:
            st.info(f"Remove **{abs(difference):.2f}** total weight.")

# Quick preset buttons
st.subheader("Quick Presets")

col1, col2, col3 = st.columns(3)

with col1:
    if st.button("Balanced", use_container_width=True):
        st.session_state.weights = {
            "severity": 0.20,
            "exploited": 0.15,
            "poc": 0.10,
            "patch": 0.15,
            "controls": 0.10,
            "asset": 0.20,
            "transfer": 0.10,
        }
        st.rerun()

with col2:
    if st.button("Threat-Focused", use_container_width=True):
        st.session_state.weights = {
            "severity": 0.20,
            "exploited": 0.25,
            "poc": 0.20,
            "patch": 0.10,
            "controls": 0.05,
            "asset": 0.15,
            "transfer": 0.05,
        }
        st.rerun()

with col3:
    if st.button("Business-Focused", use_container_width=True):
        st.session_state.weights = {
            "severity": 0.15,
            "exploited": 0.10,
            "poc": 0.05,
            "patch": 0.10,
            "controls": 0.15,
            "asset": 0.30,
            "transfer": 0.15,
        }
        st.rerun()