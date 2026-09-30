import os
import glob
import re
import requests
from dotenv import load_dotenv

load_dotenv()
api_key = os.getenv("NVD_API_KEY")

REPORTS_DIR = "scan_reports"
NVD_BASE_URL = "https://nist.gov"

def extract_cves_from_all_reports(directory_path):
    """
    Scans XML files as raw text using regex to find any CVE IDs,
    bypassing strict XML tag structural limits.
    """
    search_path = os.path.join(directory_path, "*.xml")
    xml_files = glob.glob(search_path)
    
    if not xml_files:
        print(f"Error: No XML files found inside the '{directory_path}' directory.")
        return []

    print(f"Extraction Phase: Found {len(xml_files)} report files to process.")
    master_cve_set = set()
    
    # Standard Regex pattern to find CVE-YYYY-NNNN or CVE-YYYY-NNNNN
    cve_pattern = re.compile(r"CVE-\d{4}-\d{4,7}")

    for file_path in xml_files:
        file_name = os.path.basename(file_path)
        file_cve_count = 0
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                
            # Find all strings matching the CVE pattern
            found_cves = cve_pattern.findall(content)
            
            for cve_id in found_cves:
                clean_cve = cve_id.strip()
                if clean_cve not in master_cve_set:
                    master_cve_set.add(clean_cve)
                    file_cve_count += 1
            
            print(f"Processed file: {file_name} -> Extracted {file_cve_count} new unique CVEs.")

        except Exception as e:
            print(f"Error reading file {file_name}: {e}")

    print(f"Total deduplicated master count: {len(master_cve_set)} unique CVEs ready for enrichment.")
    return list(master_cve_set)

def enrich_with_nvd(cve_list):
    """
    Queries the NVD API for the compiled list of unique CVEs.
    """
    if not cve_list:
        print("Enrichment Phase: Master CVE list is empty. Processing halted.")
        return

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept": "application/json"
    }
    if api_key:
        headers["apiKey"] = api_key.strip("'\" ")

    session = requests.Session()
    session.trust_env = False

    print("--- Starting NVD Enrichment Processing ---")
    
    # Test the pipeline with the first 3 discovered items
    for cve_id in cve_list[:3]:
        params = {"cveId": cve_id}
        try:
            response = session.get(NVD_BASE_URL, headers=headers, params=params, timeout=15)
            
            if response.status_code == 200 and "application/json" in response.headers.get("Content-Type", ""):
                json_data = response.json()
                vulnerabilities = json_data.get("vulnerabilities", [])
                
                if vulnerabilities:
                    cve_item = vulnerabilities[0].get("cve", {})
                    descriptions = cve_item.get("descriptions", [])
                    eng_desc = next((d.get("value") for d in descriptions if d.get("lang") == "en"), "No description available.")
                    
                    metrics = cve_item.get("metrics", {})
                    cvss_v31 = metrics.get("cvssMetricV31", [])
                    
                    severity = "Unknown"
                    score = "N/A"
                    if cvss_v31:
                        cvss_data = cvss_v31[0].get("cvssData", {})
                        score = cvss_data.get("baseScore", "N/A")
                        severity = cvss_data.get("baseSeverity", "Unknown")

                    print(f"Target: {cve_id} | CVSS Score: {score} ({severity})")
                    print(f"Summary: {eng_desc[:120]}...")
                    print("-" * 40)
                else:
                    print(f"Target: {cve_id} | Result: No records found in NVD registry.")
            else:
                print(f"Target: {cve_id} | API Error: Status {response.status_code}")

        except Exception as e:
            print(f"Network processing failed for {cve_id}: {e}")

if __name__ == "__main__":
    detected_cves = extract_cves_from_all_reports(REPORTS_DIR)
    enrich_with_nvd(detected_cves)
