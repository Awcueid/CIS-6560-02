import os
import glob
import re
import time
import requests
import pandas as pd
import streamlit as st
import plotly.express as px
from utils import apply_theme, render_sidebar

# Apply theme and render sidebar toggle
apply_theme()
render_sidebar()

REPORTS_DIR = "scan_reports"
BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
API_KEY = os.getenv("NVD_API_KEY", "")

def extract_cves_by_asset(directory_path):
    """ Extracts deduplicated CVE IDs mapped per target host IP from Greenbone XMLs """
    search_path = os.path.join(directory_path, "*.xml")
    xml_files = glob.glob(search_path)
    if not xml_files:
        return {}
    asset_cve_map = {}
    cve_pattern = re.compile(r"CVE-\d{4}-\d{4,7}")
    ip_pattern = re.compile(r"<host>([^<]+)</host>")

    for file_path in xml_files:
        file_name = os.path.basename(file_path)
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            ip_match = ip_pattern.search(content)
            ip_address = ip_match.group(1).strip() if ip_match else file_name.replace(".xml", "")
            if ip_address not in asset_cve_map:
                asset_cve_map[ip_address] = set()
            found_cves = cve_pattern.findall(content)
            for cve_id in found_cves:
                asset_cve_map[ip_address].add(cve_id.strip())
        except Exception:
            pass
    return {ip: list(cves) for ip, cves in asset_cve_map.items()}

def get_nvd_realtime_data(cve_id, session):
    """ Queries official NVD APIv2 endpoint for real-time triage scoring telemetry """
    headers = {"User-Agent": "Mozilla/5.0", "Accept": "application/json"}
    if API_KEY:
        headers["apiKey"] = API_KEY.strip("'\" ")
    try:
        response = session.get(BASE_URL, headers=headers, params={"cveId": cve_id}, timeout=15)
        if response.status_code == 200:
            vulnerabilities = response.json().get("vulnerabilities", [])
            if vulnerabilities:
                metrics = vulnerabilities[0].get("cve", {}).get("metrics", {})
                for version_key in ["cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                    records = metrics.get(version_key, [])
                    if records and isinstance(records, list):
                        cvss_data = records[0].get("cvssData", {})
                        return float(cvss_data.get("baseScore", 0.0)), version_key.replace("cvssMetric", "CVSS ")
            return 0.0, "None"
        elif response.status_code == 403:
            time.sleep(5)
            return get_nvd_realtime_data(cve_id, session)
        return 0.0, "API_Error"
    except Exception:
        return 0.0, "Network_Error"

def interpret_risk(score):
    if score <= 6: return "Low", "Routine monitoring is sufficient."
    if score <= 12: return "Medium", "Moderate risk requiring planned remediation."
    if score <= 18: return "High", "Significant risk. Prioritized remediation is recommended."
    return "Critical", "Severe risk requiring immediate attention."

def calculate_risk_score(cvss_score, exploited_score, poc_score, patch_score, control_score, asset_score, acceptance_score, weights):
    """ Normalized risk formula applied engine-wide """
    weighted_score = (
        (cvss_score * weights["severity"]) +
        (exploited_score * weights["exploited"]) +
        (poc_score * weights["poc"]) +
        (patch_score * weights["patch"]) +
        (control_score * weights["controls"]) +
        (asset_score * weights["asset"])
    )
    acceptance_reduction = acceptance_score * weights["transfer"]
    calculated_score = (weighted_score - acceptance_reduction) * 2.4
    return round(min(max(calculated_score, 1.0), 24.0), 1)

def simulated_threat_factors(cvss_score):
    simulated_exploited = 2 if cvss_score >= 8.5 else 1 if cvss_score >= 6.0 else 0
    simulated_poc = 2 if cvss_score >= 7.0 else 1 if cvss_score >= 4.0 else 0
    return simulated_exploited, simulated_poc

st.title("Greenbone NVD Automated Scoring Pipeline")
st.markdown("---")

weights_pipeline = st.session_state.weights
run_pipeline = st.button("Sync Reports & Run Ingestion Pipeline", use_container_width=True)

if run_pipeline:
    with st.spinner("Injecting telemetry configurations and extracting asset clusters..."):
        asset_cve_data = extract_cves_by_asset(REPORTS_DIR)
        if not asset_cve_data:
            st.error("Ingestion failure: No raw diagnostic scan telemetry files discoverable inside directory map.")
        else:
            pipeline_records = []
            session = requests.Session()
            session.trust_env = False
            delay = 1.0 if API_KEY else 6.0

            for ip_address, cve_list in asset_cve_data.items():
                max_cvss = 0.0
                context_asset_crit = 3.0
                context_controls = 1.0
                context_patch = 2.0
                context_acceptance = 0
                
                if st.session_state.get("df_assets") is not None and not st.session_state.df_assets.empty:
                    df_inv = st.session_state.df_assets
                    for idx, row in df_inv.iterrows():
                        row_str = " ".join(map(str, row.tolist()))
                        if ip_address in row_str:
                            context_asset_crit = float(row.get("critical_assets", row.get("Asset Criticality", 3.0)))
                            context_controls = float(row.get("compensating_controls", 1.0))
                            context_patch = float(row.get("patch_complexity", 2.0))
                            break

                for cve_id in cve_list[:5]:
                    score, _ = get_nvd_realtime_data(cve_id, session)
                    if score > max_cvss: max_cvss = score
                    time.sleep(delay)

                sim_exp, sim_poc = simulated_threat_factors(max_cvss)
                calculated_risk = calculate_risk_score(
                    cvss_score=max_cvss, exploited_score=sim_exp, poc_score=sim_poc,
                    patch_score=context_patch, control_score=context_controls,
                    asset_score=context_asset_crit, acceptance_score=context_acceptance, 
                    weights=weights_pipeline
                )
                risk_class, _ = interpret_risk(calculated_risk)

                pipeline_records.append({
                    "Asset Host IP": ip_address, "Max Base CVSS": max_cvss,
                    "Context Criticality": context_asset_crit, "Compensating Controls": context_controls,
                    "Calculated Engine Score": calculated_risk, "Risk Classification": risk_class,
                    "Total Target Footprint CVEs": len(cve_list)
                })

            st.session_state.df_pipeline_results = pd.DataFrame(pipeline_records)
            st.success("Telemetry pipeline synchronization complete with Compensating Controls integration!")

if st.session_state.get("df_pipeline_results") is not None and not st.session_state.df_pipeline_results.empty:
    df_p = st.session_state.df_pipeline_results
    st.subheader("Network-Wide Security Metrics")
    m1, m2, m3 = st.columns(3)
    highest_row = df_p.loc[df_p['Calculated Engine Score'].idxmax()]
    m1.metric(label="Maximum Risk Asset Score", value=f"{highest_row['Calculated Engine Score']} / 24.0", delta=highest_row['Asset Host IP'], delta_color="inverse")
    m2.metric(label="Average Network Risk Score", value=f"{round(df_p['Calculated Engine Score'].mean(), 1)} / 24.0")
    m3.metric(label="Total Monitored Endpoints", value=len(df_p))
    
    st.markdown("---")
    c1, c2 = st.columns(2)
    with c1:
        st.subheader("Asset Risk Profile Comparison")
        fig_bar = px.bar(df_p, x="Asset Host IP", y="Calculated Engine Score", color="Risk Classification",
                         color_discrete_map={"Critical": "#EF553B", "High": "#FF7F0E", "Medium": "#FECB52", "Low": "#636EFA"}, text="Calculated Engine Score")
        fig_bar.update_layout(yaxis_range=[0, 24.5])
        st.plotly_chart(fig_bar, use_container_width=True)
    with c2:
        st.subheader("Criticality Distribution Matrix")
        fig_pie = px.pie(df_p, names="Risk Classification", hole=0.4, color="Risk Classification",
                         color_discrete_map={"Critical": "#EF553B", "High": "#FF7F0E", "Medium": "#FECB52", "Low Risk": "#636EFA"})
        st.plotly_chart(fig_pie, use_container_width=True)

    st.markdown("---")
    st.subheader("Granular Scoring Pipeline Metrics")
    st.dataframe(df_p.style.background_gradient(cmap='YlOrRd', subset=['Calculated Engine Score', 'Max Base CVSS']), use_container_width=True, hide_index=True)
else:
    st.info("Click the Sync Reports button above to stream live diagnostic records through the triage pipeline matrix mapping engine.")