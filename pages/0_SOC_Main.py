import streamlit as st
import pandas as pd
import numpy as np
import os
import plotly.express as px

st.set_page_config(page_title="Vulnerability Engine", layout="wide")
st.markdown("<style>.main-title { font-size: 3.5rem; font-weight: 800; display: block; }\n.top-action-item { font-size: 0.9rem; padding: 6px 10px; background-color: #fff0f0; border-left: 4px solid #ff4b4b; margin-bottom: 6px; border-radius: 0 4px 4px 0; color: #333333; }</style>", unsafe_allow_html=True)
st.markdown('<h1 class="main-title">Context-Aware Vulnerability Prioritization Engine</h1>', unsafe_allow_html=True)
st.error("Under Development - Priotized List V1")
st.markdown("---")

@st.cache_data
def load_raw_data():
    # Load data with CISA KEV fallback logic
    p1, p2 = os.path.join("reference_data", "vulnerability_cisa_kev_enriched.xlsx"), os.path.join("reference_data", "vulnerability_contextualization_scanner_sample_updated.xlsx")
    target = p1 if os.path.exists(p1) else (p2 if os.path.exists(p2) else None)
    if not target:
        st.sidebar.error("Error: Reference data infrastructure files not found!")
        return pd.DataFrame()
    try: df = pd.read_excel(target, engine='openpyxl')
    except: df = pd.read_csv(target)
    
    if 'CISA KEV Status' not in df.columns:
        is_kev = df.get('Exploitation context', '').astype(str).str.lower().str.contains('known exploited')
        df['CISA KEV Status'] = np.where(is_kev, "Confirmed - Active Exploitation", "Standard Monitored")
        df['CISA Mandated Action'] = np.where(is_kev, "Immediate Action Required Within 24-48 Hours", "Standard Patch Cycle")
        df['CISA KEV Reference Link'] = df['CVE ID'].apply(lambda x: f"https://nist.gov{x}" if pd.notna(x) and str(x).strip() else "")
    return df[df['Finding ID'].astype(str).str.startswith('VULN-', na=False)].head(300)

vuln_data = load_raw_data()

# Left Sidebar Navigation
with st.sidebar:
    st.header("Navigation & Settings")
    taxonomy = st.selectbox("Taxonomy", ["None", "Option A-CB", "Option B-MJ", "Option C-MK"], index=1)
    # taxonomy = st.selectbox("Taxonomy", ["None", "Threat-Focused", "Balanced", "Business-Focused"], index=1)
    st.markdown("---")
    st.button("Recalculate", use_container_width=True)

norm_option = "None (Original)"

# -----------------------------------------------------------------------------
# Data Ingestion & Engine Processing
# -----------------------------------------------------------------------------

if taxonomy == "Option B":
    from engines.taxonomy_b_engine import run_option_b_engine
    vuln_data = run_option_b_engine(vuln_data)

# Main Dashboard Metrics Computation
total = len(vuln_data)
status, mttr, uniq_cves, crit_vulns, crit_delta, top_actions = "Stable", "N/A", "0\n(No CVE: 0)", 0, "No Data Available", []

if total > 0:
    cves = vuln_data['CVE ID'].dropna() if 'CVE ID' in vuln_data.columns else pd.Series()
    uniq_cves = f"{cves.nunique():,}\n(No CVE: {vuln_data['CVE ID'].isna().sum() if 'CVE ID' in vuln_data.columns else 0:,})"
    
    if 'CVSS severity' in vuln_data.columns:
        crit_df = vuln_data[vuln_data['CVSS severity'] == 'Critical']
        crit_vulns = len(crit_df)
        if crit_vulns > 0 and 'Asset group' in crit_df.columns:
            crit_delta = " | ".join(crit_df['Asset group'].value_counts().index[:3].astype(str))

    if 'Contextual priority' in vuln_data.columns:
        p1_cnt = vuln_data['Contextual priority'].astype(str).str.contains('P1', case=False, na=False).sum()
        status = "High Risk" if p1_cnt >= 10 else ("Medium Risk" if p1_cnt >= 1 else "Stable")
        if 'CVSS base score' in vuln_data.columns:
            p1_df = vuln_data[vuln_data['Contextual priority'].astype(str).str.contains('P1', case=False, na=False)].copy()
            p1_df['CVSS base score'] = pd.to_numeric(p1_df['CVSS base score'], errors='coerce')
            for _, r in p1_df.sort_values('CVSS base score', ascending=False).head(5).iterrows():
                top_actions.append(f"{str(r.get('CVE ID', 'No CVE')).strip()} [{r.get('Asset group', '')}]: {str(r.get('Vulnerability title', '')).strip()}")

    if 'Estimated remediation effort' in vuln_data.columns:
        def to_days(x):
            v = str(x).lower()
            if 'hour' in v: return 0.2
            nums = [int(s) for s in v.replace('–', '-').split('-') if s.isdigit()]
            return (sum(nums)/len(nums) if nums else 2.0) * (7.0 if 'week' in v else 1.0)
        efforts = vuln_data['Estimated remediation effort'].apply(to_days).dropna()
        if not efforts.empty: mttr = f"{efforts.mean():.1f} Days"

# Layout Components Rendering
col_status, col_chart = st.columns(2)
with col_status:
    st.metric("Status", status)
    
    # ----------------------------------------------------------------------
    # Recalculate Contextual Priority
    # ----------------------------------------------------------------------
    if total > 0 and 'Contextual priority' in vuln_data.columns:
        st.markdown("<p style='font-size: 1.1rem; font-weight:700; margin-top:15px;'>Vulnerability by Contextual Priority</p>", unsafe_allow_html=True)
        
        priority_df = vuln_data['Contextual priority'].value_counts().reset_index(name='Count')
        
        fig_priority = px.pie(
            priority_df, 
            values='Count', 
            names='Contextual priority', 
            hole=0.4, 
            color_discrete_sequence=px.colors.sequential.OrRd_r
        )
        fig_priority.update_traces(textposition='inside', textinfo='percent+value')
        fig_priority.update_layout(margin=dict(t=10, b=15, l=0, r=0), height=350)
        
        st.plotly_chart(fig_priority, use_container_width=True)
    
    if top_actions:
        st.markdown("<p style='font-size: 1.1rem; font-weight:700; margin-top:15px;'>Immediate Action Required (Top 5):</p>", unsafe_allow_html=True)
        for act in top_actions: 
            st.markdown(f"<div class='top-action-item'>{act}</div>", unsafe_allow_html=True)
    elif total > 0: 
        st.markdown("<p style='color:green; font-weight:600; margin-top:15px;'>No active P1 vulnerabilities found.</p>", unsafe_allow_html=True)


with col_chart:
    if total > 0 and 'Asset group' in vuln_data.columns:
        gdf = vuln_data['Asset group'].value_counts().reset_index(name='Count')
        fig = px.pie(gdf, values='Count', names='Asset group', title='Vulnerability Distribution by Asset Group', hole=0.4, color_discrete_sequence=px.colors.sequential.RdBu)
        fig.update_traces(textposition='inside', textinfo='percent+value').update_layout(margin=dict(t=40, b=0, l=0, r=0), height=600)
        st.plotly_chart(fig, use_container_width=True)

st.markdown("---")

metrics_data = [
    {"label": "Critical", "val": f"{crit_vulns}", "delta": crit_delta if crit_delta != "No Data Available" else None},
    {"label": "Est. MTTR", "val": mttr, "delta": None},
]

col_total, col_critical, col_mttr = st.columns(3)

with col_total:
    st.metric(
        label="Total Findings",
        value=f"{total:,}",
        delta=None,
    )
    st.markdown(f"Unique CVEs: {uniq_cves}")

with col_critical:
    st.metric(
        label="Critical",
        value=f"{crit_vulns}",
        delta=crit_delta if crit_delta != "No Data Available" else None,
        delta_color="inverse" if crit_delta and crit_delta != "No Data Available" else "normal",
    )

with col_mttr:
    st.metric(
        label="Est. MTTR",
        value=mttr,
        delta=None,
    )

st.markdown("---")

# Extracted row styling handler to solve f-string nested token limitations
def get_severity_styles(row):
    color_map = {'critical': '#ffcccc; color: #990000; font-weight: bold', 'high': '#ffe6cc; color: #b35900; font-weight: bold', 'medium': '#ffffcc; color: #808000', 'low': '#e6ffcc; color: #336600'}
    severity = str(row.get('CVSS severity', '')).strip().lower()
    style = f"background-color: {color_map[severity]}" if severity in color_map else ""
    return [style] * len(row)

def render_queue(df_source):
    if len(df_source) == 0:
        st.warning("No data available for this queue view.")
        return

    df_disp = df_source.copy()

    # Add row numbers
    df_disp.insert(0, "No.", np.arange(1, len(df_disp) + 1))

    # Remove internal columns
    df_disp = df_disp.drop(
        columns=[c for c in ["Finding ID", "Data status"] if c in df_disp.columns]
    )

    # Build valid NVD detail links
    if "CVE ID" in df_disp.columns:
        df_disp["CVE ID"] = df_disp["CVE ID"].astype(str).str.strip()

        df_disp["NVD Details"] = df_disp["CVE ID"].apply(
            lambda cve: (
                f"https://nvd.nist.gov/vuln/detail/{cve}"
                if cve and cve.lower() != "nan"
                else ""
            )
        )

    # Put the most important columns first
    priority_columns = [
        "No.",
        "Vulnerability title",
        "CVE ID",
        "CISA KEV Status",
        "CISA Mandated Action",
        "CISA KEV Feed Link",
        "NVD Details",
    ]

    # Keep only columns that actually exist, in the requested order
    ordered_columns = [c for c in priority_columns if c in df_disp.columns]

    # Add every remaining column after the priority columns
    remaining_columns = [c for c in df_disp.columns if c not in ordered_columns]
    df_disp = df_disp[ordered_columns + remaining_columns]

    # Numeric formatting
    fmt = {
        key: value
        for key, value in [
            ("CVSS base score", "{:.1f}"),
            ("Normalized Score", "{:.2f}"),
        ]
        if key in df_disp.columns
    }

    # Column display configuration
    cfg = {
        "No.": st.column_config.NumberColumn("No.", format="%d"),
        "Vulnerability title": st.column_config.TextColumn("Vulnerability Title"),
        "CVE ID": st.column_config.TextColumn("CVE ID"),
        "CISA KEV Status": st.column_config.TextColumn("CISA KEV Status"),
        "CISA Mandated Action": st.column_config.TextColumn("CISA Mandated Action"),
        "CISA KEV Feed Link": st.column_config.LinkColumn(
            "CISA KEV Feed Link",
            display_text="Open CISA Portal",
        ),
        "NVD Details": st.column_config.LinkColumn(
            "NVD Details",
            display_text="Open NVD",
        ),
        "Normalized Score": st.column_config.NumberColumn(
            "Normalized Score",
            format="%.2f",
        ),
    }

    st.dataframe(
        df_disp.style.apply(get_severity_styles, axis=1).format(fmt, na_rep=""),
        use_container_width=True,
        height=650,
        hide_index=True,
        column_config=cfg,
    )


tab_option_a, tab_option_b, tab_option_c, tab_cisa, tab_all = st.tabs(
    [
        "Option A",
        "Option B",
        "Option C",
        "CISA KEV Validated Queue",
        "Queue",
    ]
)


# -----------------------------
# Option A
# -----------------------------
with tab_option_a:
    st.subheader("Option A: Threat-Focused - In Development")

    if taxonomy == "Option A":
        st.info("Option A taxonomy queue is not connected yet.")
        # render_queue(df_taxonomy_queue_a)
    else:
        st.info("Please select **Option A** to view this queue.")


# -----------------------------
# Option B
# -----------------------------
with tab_option_b:
    st.subheader("Option B: Balanced - In Development")

    if taxonomy == "Option B":
        if "Normalized Score" in vuln_data.columns:
            sorted_taxonomy_data_b = vuln_data.sort_values(
                by="Normalized Score",
                ascending=False,
            )
            render_queue(sorted_taxonomy_data_b)
        else:
            st.error(
                "Engine failure: 'Normalized Score' column not found in dataset."
            )
    else:
        st.info("Please select **Option B** to view this queue.")


# -----------------------------
# Option C
# -----------------------------
with tab_option_c:
    st.subheader("Option C: Business-Focused")

    if taxonomy == "Option C":
        st.info("Option C taxonomy queue is not connected yet.")
          # render_queue(df_taxonomy_queue_c)
    else:
        st.info("Please select **Option C** to view this queue.")


# -----------------------------
# CISA KEV
# -----------------------------
with tab_cisa:
    st.subheader("CISA KEV Validated Queue")

    if "CISA KEV Status" in vuln_data.columns:
        cisa_filtered_data = vuln_data[
            vuln_data["CISA KEV Status"] == "Confirmed - Active Exploitation"
        ]
    else:
        cisa_filtered_data = pd.DataFrame()

    render_queue(cisa_filtered_data)


# -----------------------------
# All findings
# -----------------------------
with tab_all:
    st.subheader("Queue")
    render_queue(vuln_data)
