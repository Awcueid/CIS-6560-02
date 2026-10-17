import json
import os
import requests
import pandas as pd
import streamlit as st

from utils import render_sidebar_menu


st.set_page_config(
    page_title="SOC Dashboard",
    layout="wide"
)


# Define file paths
EXCEL_FILE = "reference_data/vulnerability_contextualization_scanner_sample_updated.xlsx"
TAXONOMY_CONFIG_FILE = "taxonomy_config.json"


# Initialize or load taxonomy configuration file
def load_or_init_taxonomy():
    if not os.path.exists(TAXONOMY_CONFIG_FILE):
        default_config = {
            "taxonomy_metadata": {
                "current_version": "v1.2.0",
                "history": [
                    {
                        "version": "v1.2.0",
                        "effective_date": "2026-10-15",
                        "description": "Initial default taxonomy"
                    }
                ]
            },
            "severity_weights": {
                "Critical": 10.0,
                "High": 8.0,
                "Medium": 5.0,
                "Low": 2.0,
                "Info": 0.0
            }
        }
        with open(TAXONOMY_CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(default_config, f, indent=4, ensure_ascii=False)
        return default_config

    with open(TAXONOMY_CONFIG_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


# Save taxonomy configuration changes
def save_taxonomy(config):
    with open(TAXONOMY_CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=4, ensure_ascii=False)


# Load scanner findings data with caching
@st.cache_data
def load_scanner_data(file_path):
    if not os.path.exists(file_path):
        return pd.DataFrame()
    return pd.read_excel(file_path, sheet_name="Scanner Findings")


# Load configuration and dataset
taxonomy_data = load_or_init_taxonomy()
df_findings = load_scanner_data(EXCEL_FILE)


# Initialize Session State for weights and taxonomy version
if "weights" not in st.session_state:
    st.session_state.weights = taxonomy_data.get("severity_weights", {
        "Critical": 10.0,
        "High": 8.0,
        "Medium": 5.0,
        "Low": 2.0,
        "Info": 0.0
    })


if "taxonomy_version" not in st.session_state:
    st.session_state.taxonomy_version = taxonomy_data.get(
        "taxonomy_metadata", {}
    ).get("current_version", "v1.2.0")


# --- Sidebar (Left Side): Navigation Menu ---
selected_module = render_sidebar_menu()


# --- Main Screen (Right Side): Module Rendering Logic ---
st.header("SOC Dashboard")
st.markdown("---")


if selected_module == "Risk Weight Tuning":
    st.subheader("Risk Weight Tuning")
    st.markdown("Configure and adjust dynamic severity weights.")

    current_weights = st.session_state.weights

    with st.form("taxonomy_form"):
        new_version = st.text_input(
            "Taxonomy Version",
            value=st.session_state.taxonomy_version
        )
        change_desc = st.text_area(
            "Change Description",
            value="Tuned risk weights for operational priority"
        )

        st.markdown("---")
        st.subheader("Risk Weight Tuning by Severity")

        updated_weights = {}
        col1, col2 = st.columns(2)

        with col1:
            for sev in ["Critical", "High"]:
                default_val = float(current_weights.get(sev, 1.0))
                updated_weights[sev] = st.number_input(
                    f"{sev} Weight",
                    value=default_val,
                    step=0.5
                )

        with col2:
            for sev in ["Medium", "Low", "Info"]:
                default_val = float(current_weights.get(sev, 1.0))
                updated_weights[sev] = st.number_input(
                    f"{sev} Weight",
                    value=default_val,
                    step=0.5
                )

        submitted = st.form_submit_button("Save and Apply Settings")

        if submitted:
            st.session_state.weights = updated_weights
            st.session_state.taxonomy_version = new_version

            taxonomy_data["severity_weights"] = updated_weights
            taxonomy_data["taxonomy_metadata"]["current_version"] = new_version
            taxonomy_data["taxonomy_metadata"]["history"].append({
                "version": new_version,
                "effective_date": pd.Timestamp.now().strftime("%Y-%m-%d %H:%M:%S"),
                "description": change_desc
            })
            save_taxonomy(taxonomy_data)

            st.success(
                f"Taxonomy configuration updated successfully! "
                f"(Current Version: {new_version})"
            )
            st.rerun()


elif selected_module == "Sample Dataset":
    st.subheader("Sample Dataset")
    st.markdown("Inspect and manage scanner sample datasets.")

    if not df_findings.empty:
        st.dataframe(df_findings.head(50), use_container_width=True)
    else:
        st.info("Sample dataset file not loaded.")


elif selected_module == "NVD API Search Query":
    st.subheader("NVD API Search Query")
    st.markdown("Execute and test live NVD vulnerability queries.")

    cve_input = st.text_input(
        "Enter CVE ID (e.g., CVE-2021-44228)",
        value=st.session_state.get("cve_input", "")
    )

    nvd_api_key = st.text_input(
        "NVD API Key (optional)",
        type="password",
        help="Optional. Required for higher request rates."
    )

    if st.button("Search NVD"):
        cve_id = cve_input.strip().upper()

        if not cve_id:
            st.warning("Please enter a valid CVE ID.")
        else:
            st.session_state["cve_input"] = cve_id

            url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
            params = {"cveId": cve_id}
            headers = {}

            if nvd_api_key:
                headers["apiKey"] = nvd_api_key

            try:
                with st.spinner(f"Querying NVD API for {cve_id}..."):
                    response = requests.get(
                        url,
                        params=params,
                        headers=headers,
                        timeout=30
                    )

                if response.status_code != 200:
                    st.error(
                        f"NVD API request failed. "
                        f"HTTP {response.status_code}: {response.text}"
                    )
                else:
                    data = response.json()
                    vulnerabilities = data.get("vulnerabilities", [])

                    if not vulnerabilities:
                        st.warning(f"No NVD result found for {cve_id}.")
                    else:
                        cve_item = vulnerabilities[0].get("cve", {})
                        result_cve_id = cve_item.get("id", cve_id)

                        descriptions = cve_item.get("descriptions", [])
                        description = ""

                        for desc in descriptions:
                            if desc.get("lang") == "en":
                                description = desc.get("value", "")
                                break

                        metrics = cve_item.get("metrics", {})
                        cvss_v31 = metrics.get("cvssMetricV31", [])
                        cvss_v30 = metrics.get("cvssMetricV30", [])
                        cvss_v2 = metrics.get("cvssMetricV2", [])

                        base_score = None
                        severity = None
                        vector_string = None

                        if cvss_v31:
                            cvss_data = cvss_v31[0].get("cvssData", {})
                            base_score = cvss_data.get("baseScore")
                            severity = cvss_data.get("baseSeverity")
                            vector_string = cvss_data.get("vectorString")
                        elif cvss_v30:
                            cvss_data = cvss_v30[0].get("cvssData", {})
                            base_score = cvss_data.get("baseScore")
                            severity = cvss_data.get("baseSeverity")
                            vector_string = cvss_data.get("vectorString")
                        elif cvss_v2:
                            cvss_data = cvss_v2[0].get("cvssData", {})
                            base_score = cvss_data.get("baseScore")
                            severity = cvss_v2[0].get("baseSeverity")
                            vector_string = cvss_data.get("vectorString")

                        st.success(f"NVD result found for {result_cve_id}.")

                        col1, col2, col3 = st.columns(3)

                        with col1:
                            st.metric(
                                "CVSS Base Score",
                                base_score if base_score is not None else "N/A"
                            )

                        with col2:
                            st.metric(
                                "Severity",
                                severity if severity else "N/A"
                            )

                        with col3:
                            st.metric(
                                "Published",
                                cve_item.get("published", "N/A")
                            )

                        st.markdown("---")
                        st.subheader("Description")
                        st.write(
                            description
                            if description
                            else "No English description available."
                        )

                        st.subheader("CVSS Vector String")
                        st.code(vector_string if vector_string else "N/A")

                        st.subheader("References")
                        references = cve_item.get("references", [])

                        if references:
                            for reference in references:
                                ref_url = reference.get("url")
                                if ref_url:
                                    st.markdown(f"- [{ref_url}]({ref_url})")
                        else:
                            st.info("No references available.")

            except requests.exceptions.RequestException as e:
                st.error(f"Could not connect to the NVD API: {e}")
            except ValueError:
                st.error("NVD API returned an invalid JSON response.")