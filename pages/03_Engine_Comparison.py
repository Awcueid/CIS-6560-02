import streamlit as st
import pandas as pd
import numpy as np
import os
from engines.taxonomy_b_engine import run_option_b_engine

st.set_page_config(page_title="Engine Comparison", layout="wide")

st.markdown("<style>.main-title { font-size: 2.8rem; font-weight: 800; }</style>", unsafe_allow_html=True)
st.markdown('<h1 class="main-title">Multi-Engine Risk Score Comparison</h1>', unsafe_allow_html=True)
st.error("Under Development")
st.markdown("---")

@st.cache_data
def load_comparison_data():
    """Loads raw dataset from project infrastructure reference directory."""
    p1 = os.path.join("reference_data", "vulnerability_cisa_kev_enriched.xlsx")
    p2 = os.path.join("reference_data", "vulnerability_contextualization_scanner_sample_updated.xlsx")
    target = p1 if os.path.exists(p1) else (p2 if os.path.exists(p2) else None)
    
    if not target:
        st.error("Reference data infrastructure files not found!")
        return pd.DataFrame()
        
    try: return pd.read_excel(target, engine='openpyxl')
    except: return pd.read_csv(target)

# Process raw data and apply engines in parallel
df_raw = load_comparison_data()
df_raw = df_raw[df_raw['Finding ID'].astype(str).str.startswith('VULN-', na=False)] if 'Finding ID' in df_raw.columns else df_raw

if not df_raw.empty:
    # 1. Generate clean Dataframe copies for parallel benchmarking
    df_original = df_raw.copy()
    df_option_a = df_raw.copy() # Reserved for Option A
    df_option_b = run_option_b_engine(df_raw.copy())

    # 2. Key Metadata Resolution Logic (Fuzzy column identifier matching)
    cve_col = next((c for c in df_original.columns if c.replace('_','').replace(' ','').lower() == 'cveid'), None)
    title_col = next((c for c in df_original.columns if c.replace('_','').replace(' ','').lower() == 'vulnerabilitytitle'), None)
    prof_priority = next((c for c in df_original.columns if c.replace('_','').replace(' ','').lower() == 'contextualpriority'), None)
    cvss_col = next((c for c in df_original.columns if c.replace('_','').replace(' ','').lower() == 'cvssbasescore'), None)

    if cve_col and cvss_col:
        # Build comparison dataset
        comp_matrix = pd.DataFrame({
            "CVE ID": df_original[cve_col],
            "Vulnerability Title": df_original[title_col] if title_col else "N/A",
            "Raw CVSS Base": df_original[cvss_col],
            "Prof. Baseline (Label)": df_original[prof_priority] if prof_priority else "N/A",
            "Option A Score": "TBD (Under Dev)",
            "Option B Score": df_option_b['Normalized Score'] if 'Normalized Score' in df_option_b.columns else 0.0
        })

        # Calculate Priority Shifting Delta for analytics view
        comp_matrix['CVSS Adjusted Score'] = comp_matrix['Raw CVSS Base'] * 10
        comp_matrix['Priority Shift Delta'] = comp_matrix['Option B Score'] - comp_matrix['CVSS Adjusted Score']
        
        # Sort by highest dynamic threat score
        comp_matrix = comp_matrix.sort_values(by="Option B Score", ascending=False)

        # 3. Dynamic Filtering Metrics Row
        col1, col2, col3 = st.columns(3)
        col1.metric("Total Benchmarked Items", f"{len(comp_matrix):,}")
        
        up_shifts = (comp_matrix['Priority Shift Delta'] > 15).sum()
        down_shifts = (comp_matrix['Priority Shift Delta'] < -15).sum()
        col2.metric("Risk Escalations (Option B Raised)", f"{up_shifts} CVEs", delta="Critical Focus", delta_color="inverse")
        col3.metric("Risk De-escalations (Noise Reduced)", f"{down_shifts} CVEs", delta="Alert Fatigue Fixed")

        st.markdown("### Score Comparison Grid View")
        
        # Color coding rule injector for priority shift cells
        def highlight_shifts(row):
            delta = row['Priority Shift Delta']
            if delta > 15: return ['background-color: #ffebec; color: #cc0000'] * len(row) # Escalated risk
            if delta < -15: return ['background-color: #eafaf1; color: #27ae60'] * len(row) # Safely mitigated noise
            return [''] * len(row)

        # Hide temporary computing column before rendering 
        final_render = comp_matrix.drop(columns=['CVSS Adjusted Score'])

        # Display Dataframe Grid Layout
        st.dataframe(
            final_render.style.apply(highlight_shifts, axis=1),
            use_container_width=True,
            height=600,
            hide_index=True,
            column_config={
                "Raw CVSS Base": st.column_config.NumberColumn("Raw CVSS", format="%.1f"),
                "Option B Score": st.column_config.NumberColumn("Option B Score", format="%.2f"),
                "Priority Shift Delta": st.column_config.NumberColumn("Priority Shift Delta", format="%+.2f")
            }
        )
    else:
        st.error("Error: Core identification columns are missing from the parsed dataset.")
else:
    st.warning("No reference data available to compute comparison metrics.")
