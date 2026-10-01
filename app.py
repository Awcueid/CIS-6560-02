import os
import requests
import pandas as pd
import streamlit as st
from dotenv import load_dotenv


# ==========================================
# 1. INITIALIZATION
# ==========================================
load_dotenv()

API_KEY = os.getenv("NVD_API_KEY")
BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

st.set_page_config(
    page_title="SOC Dashboard - CIS6560 Sec02 - Context-Aware Vulnerability Prioritization",
    layout="wide"
)

st.markdown("""
<style>
    .block-container {
        padding-top: 1rem;
        padding-bottom: 0rem;
        max-width: 100%;
    }

    h1 {
        margin-top: 0rem;
        margin-bottom: 0.5rem;
        font-size: 1.8rem !important;
    }

    h3 {
        margin-top: 0rem;
        margin-bottom: 0.3rem;
        font-size: 1.2rem !important;
    }

    .stMarkdown div p {
        margin-bottom: 0.2rem;
    }

    div[data-testid="stForm"] {
        padding: 0.5rem;
    }
</style>
""", unsafe_allow_html=True)

st.title("CIS6560 Security Risk Scoring and CVE Dashboard")


# ==========================================
# 2. SESSION STATE
# ==========================================
if "nvd_data" not in st.session_state:
    st.session_state.nvd_data = None

if "last_keyword" not in st.session_state:
    st.session_state.last_keyword = ""

if "last_limit" not in st.session_state:
    st.session_state.last_limit = 30

if "has_fetched" not in st.session_state:
    st.session_state.has_fetched = False

if "df_assets" not in st.session_state:
    st.session_state.df_assets = None


# ==========================================
# 3. HELPER FUNCTIONS
# ==========================================
@st.cache_data(ttl=600, show_spinner=False)
def fetch_nvd_data(query_keyword, limit, api_key_present):
    """
    Retrieve CVEs from the NVD CVE API 2.0.
    Cached for 10 minutes to reduce API calls.
    """
    params = {
        "resultsPerPage": limit
    }

    if query_keyword and query_keyword.strip():
        params["keywordSearch"] = query_keyword.strip()

    headers = {}

    if api_key_present and API_KEY:
        headers["apiKey"] = API_KEY

    try:
        response = requests.get(
            BASE_URL,
            headers=headers,
            params=params,
            timeout=20
        )
        response.raise_for_status()
        return response.json(), None

    except requests.exceptions.Timeout:
        return None, "The NVD API request timed out. Please try again."

    except requests.exceptions.HTTPError:
        error_message = (
            f"NVD API returned HTTP {response.status_code}. "
            "If you made several requests recently, wait briefly and retry."
        )
        return None, error_message

    except requests.exceptions.RequestException as error:
        return None, f"Connection error while contacting NVD: {error}"


def get_cvss_metrics(cve_core):
    """
    Safely extract the preferred available CVSS score:
    CVSS v3.1 -> CVSS v3.0 -> CVSS v2.

    NVD stores cvssMetricV31, cvssMetricV30, and cvssMetricV2
    as lists, not direct dictionaries.
    """
    metrics = cve_core.get("metrics", {})

    metric_priority = [
        ("cvssMetricV40", "CVSS v4.0"),
        ("cvssMetricV31", "CVSS v3.1"),
        ("cvssMetricV30", "CVSS v3.0"),
        ("cvssMetricV2", "CVSS v2.0"),
    ]

    for metric_key, metric_version in metric_priority:
        metric_records = metrics.get(metric_key, [])

        if metric_records and isinstance(metric_records, list):
            first_metric = metric_records[0]
            cvss_data = first_metric.get("cvssData", {})

            return {
                "score": float(cvss_data.get("baseScore", 0.0)),
                "severity": cvss_data.get("baseSeverity", "Unknown"),
                "version": metric_version,
                "vector": cvss_data.get("vectorString", "Not available")
            }

    return {
        "score": 0.0,
        "severity": "Not Rated",
        "version": "No CVSS data",
        "vector": "Not available"
    }


def interpret_risk(score):
    """
    Convert the custom 1–24 risk score into a risk category.
    """
    if score <= 6:
        return "Low", "Routine monitoring is sufficient."

    if score <= 12:
        return "Medium", "Moderate risk requiring planned remediation."

    if score <= 18:
        return "High", "Significant risk. Prioritized remediation is recommended."

    return "Critical", "Severe risk requiring immediate attention."


def calculate_risk_score(
    cvss_score,
    exploited_score,
    poc_score,
    patch_score,
    control_score,
    asset_score,
    acceptance_score,
    weights
):
    """
    Produces a normalized 1–24 classroom risk score.

    Risk acceptance is treated as a reduction factor, because accepted
    or transferred risk should lower the residual score rather than raise it.
    """
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
    """
    Classroom simulation only.

    These values do not confirm real-world exploitation or public proof-of-
    concept availability. They are estimates derived from severity so the
    dashboard can demonstrate weighted risk calculations.
    """
    simulated_exploited = 2 if cvss_score >= 8.5 else 1 if cvss_score >= 6.0 else 0
    simulated_poc = 2 if cvss_score >= 7.0 else 1 if cvss_score >= 4.0 else 0

    return simulated_exploited, simulated_poc


# ==========================================
# 4. PAGE LAYOUT
# ==========================================
main_col, config_col = st.columns([1.8, 1.2], gap="medium")


# ==========================================
# 5. SEARCH CONTROLS
# ==========================================
with main_col:
    with st.container(border=True):
        st.subheader("NVD API Search Query")

        input_col, slider_col = st.columns(2)

        with input_col:
            keyword = st.text_input(
                "Search Keyword",
                placeholder="Example: CVE-1999-0524, Apache, Microsoft, OpenSSL"
            )

        with slider_col:
            results_per_page = st.slider(
                "Max Results to Fetch",
                min_value=5,
                max_value=100,
                value=30,
                step=5
            )

        fetch_button = st.button(
            "Fetch and Run Analysis Matrix",
            use_container_width=True,
            type="primary"
        )

        st.caption(
            "Leave the keyword blank to retrieve the most recently published CVE entries."
        )


# ==========================================
# 6. WEIGHT CONTROLS
# ==========================================
with config_col:
    with st.container(border=True):
        st.subheader("Risk Weight Tuning Options")

        w_severity = st.slider(
            "Severity (CVSS)",
            0.0, 1.0, 0.40, 0.05,
            key="sev"
        )

        w_exploited = st.slider(
            "Simulated Exploited in Wild",
            0.0, 1.0, 0.15, 0.05,
            key="exp"
        )

        w_poc = st.slider(
            "Simulated PoC Availability",
            0.0, 1.0, 0.10, 0.05,
            key="poc"
        )

        w_patch = st.slider(
            "Patch Difficulty",
            0.0, 1.0, 0.10, 0.05,
            key="patch"
        )

        w_controls = st.slider(
            "Compensating Controls",
            0.0, 1.0, 0.10, 0.05,
            key="ctrl"
        )

        w_asset = st.slider(
            "Asset Criticality",
            0.0, 1.0, 0.10, 0.05,
            key="asset"
        )

        w_transfer = st.slider(
            "Risk Acceptance / Transfer",
            0.0, 1.0, 0.05, 0.05,
            key="trans"
        )

        total_weight = round(
            w_severity +
            w_exploited +
            w_poc +
            w_patch +
            w_controls +
            w_asset +
            w_transfer,
            2
        )

        if total_weight == 1.00:
            st.success(f"Weights verified: total = {total_weight:.2f}")
        else:
            st.error(
                f"Weights invalid: must equal 1.00 "
                f"(current total: {total_weight:.2f})"
            )

        st.caption(
            "Exploitation and PoC values are simulated from CVSS severity "
            "for instructional use and are not threat-intelligence findings."
        )


# ==========================================
# 7. FETCH NEW DATA ONLY ON BUTTON PRESS
# ==========================================
if fetch_button:
    if total_weight != 1.00:
        st.error("Correct the risk weights so they total exactly 1.00 before running analysis.")

    else:
        with st.spinner("Retrieving vulnerability data from the NVD API..."):
            data, error = fetch_nvd_data(
                keyword,
                results_per_page,
                bool(API_KEY)
            )

        if error:
            st.error(error)

        elif data and "vulnerabilities" in data:
            st.session_state.nvd_data = data
            st.session_state.last_keyword = keyword
            st.session_state.last_limit = results_per_page
            st.session_state.has_fetched = True

        else:
            st.error("The NVD API returned no readable vulnerability records.")


# ==========================================
# 8. ANALYTICS DISPLAY
# ==========================================
with main_col:
    if not st.session_state.has_fetched:
        st.info(
            "Enter a keyword or leave it blank, choose the number of records, "
            "then select **Fetch and Run Analysis Matrix**."
        )

    elif st.session_state.nvd_data:
        data = st.session_state.nvd_data
        cve_list = []

        for item in data.get("vulnerabilities", []):
            cve_core = item.get("cve", {})

            cve_id = cve_core.get("id", "Unknown CVE")

            descriptions = cve_core.get("descriptions", [])
            english_desc = next(
                (
                    description.get("value", "No English description available.")
                    for description in descriptions
                    if description.get("lang") == "en"
                ),
                "No English description available."
            )

            published_date = cve_core.get("published", "Not available")
            last_modified_date = cve_core.get("lastModified", "Not available")

            cvss = get_cvss_metrics(cve_core)
            cvss_score = cvss["score"]

            sim_exploited, sim_poc = simulated_threat_factors(cvss_score)

            # Classroom assumptions; make these editable per-asset in a future version.
            sim_patch = 2
            sim_controls = 1
            sim_asset = 3
            sim_transfer = 0

            weights = {
                "severity": w_severity,
                "exploited": w_exploited,
                "poc": w_poc,
                "patch": w_patch,
                "controls": w_controls,
                "asset": w_asset,
                "transfer": w_transfer
            }

            final_score = calculate_risk_score(
                cvss_score=cvss_score,
                exploited_score=sim_exploited,
                poc_score=sim_poc,
                patch_score=sim_patch,
                control_score=sim_controls,
                asset_score=sim_asset,
                acceptance_score=sim_transfer,
                weights=weights
            )

            risk_level, risk_interpretation = interpret_risk(final_score)

            cve_list.append({
                "CVE ID": cve_id,
                "CVSS Version": cvss["version"],
                "CVSS Score": cvss_score,
                "CVSS Severity": cvss["severity"],
                "Calculated Risk Score": final_score,
                "Risk Level": risk_level,
                "Interpretation": risk_interpretation,
                "Published": published_date,
                "Last Modified": last_modified_date,
                "Description": english_desc
            })

        df = pd.DataFrame(cve_list)

        if df.empty:
            st.warning("No CVE records were returned for this query.")

        else:
            df_sorted = df.sort_values(
                by="Calculated Risk Score",
                ascending=False
            ).reset_index(drop=True)

            search_label = st.session_state.last_keyword.strip()

            if search_label:
                block_title = (
                    f"Risk Distribution: Search Results for '{search_label}'"
                )
            else:
                block_title = "Risk Distribution: Most Recent CVE Entries"

            with st.container(border=True):
                st.subheader(block_title)

                chart_df = df_sorted.head(10)

                st.bar_chart(
                    chart_df,
                    x="CVE ID",
                    y="Calculated Risk Score",
                    use_container_width=True
                )

            with st.container(border=True):
                st.subheader("Comprehensive Calculated Data Records")

                st.dataframe(
                    df_sorted,
                    use_container_width=True,
                    hide_index=True,
                    column_config={
                        "CVSS Score": st.column_config.NumberColumn(
                            format="%.1f"
                        ),
                        "Calculated Risk Score": st.column_config.NumberColumn(
                            format="%.1f"
                        )
                    }
                )

                csv_data = df_sorted.to_csv(index=False).encode("utf-8")

                st.download_button(
                    label="Download Results as CSV",
                    data=csv_data,
                    file_name="cve_risk_analysis.csv",
                    mime="text/csv",
                    use_container_width=True
                )

    # ==========================================
    # 9. INLINE EDITABLE ASSET INVENTORY FROM FILE
    # ==========================================
    st.write("---")
    st.subheader("Asset Management & Control Mapping")
    st.caption("Edit values directly inside the table grid below. Changes are saved implicitly.")

    csv_file_path = "Inventory_Lists.csv"


    if st.session_state.df_assets is None:
        if os.path.exists(csv_file_path):
            try:
                st.session_state.df_assets = pd.read_csv(csv_file_path, nrows=7)
            except Exception as error:
                st.error(f"Error reading file: {error}")
        else:
            st.warning(f"File not found. Looking for '{csv_file_path}' in the same directory as app.py.")

    # Render data grid frame if data state is active
    if st.session_state.df_assets is not None:
        edited_df = st.data_editor(
            st.session_state.df_assets,
            use_container_width=True,
            hide_index=True,
            num_rows="dynamic"
        )
        # Capture grid overrides back into active state memory
        st.session_state.df_assets = edited_df
        
        # Action controls layout located directly under the grid
        stat_col, action_col = st.columns([1,1])
        with stat_col:
            st.metric(label="Total Tracked Assets", value=len(st.session_state.df_assets))
        with action_col:
            # Force action button to smash old session states and reload fresh disk file data
            if st.button("Reload from CSV File", use_container_width=True):
                if os.path.exists(csv_file_path):
                    try:
                        st.session_state.df_assets = pd.read_csv(csv_file_path, nrows=7)
                        st.success("Successfully synchronized from disk file.")
                        st.rerun()
                    except Exception as error:
                        st.error(f"Failed to read disk file: {error}")
                else:
                    st.error(f"Cannot reload. '{csv_file_path}' is missing from the directory.")
