import xml.etree.ElementTree as ET
import json
import os
import requests  # Required for making HTTP requests to the NVD API
from dotenv import load_dotenv  # Safely load configuration settings from .env file

# Initialize and load environment variables from the local .env file
load_dotenv()
api_key = os.getenv("NVD_API_KEY")

# The exact base URL for the entire v2.0 endpoint tree
BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

class SecurityDataPipeline:
    def __init__(self, xml_path, taxonomy_path):
        self.xml_path = xml_path
        self.taxonomy_path = taxonomy_path
        
    def fetch_nvd_data(self, cve_id):
        """Connects to the NIST NVD API to fetch the latest CVSS and vulnerability metadata"""
        if cve_id == "N/A" or not cve_id:
            return None
            
        # Combine the central base URL with the specific CVE lookup query string
        url = f"{BASE_URL}?cveId={cve_id}"
        
        headers = {
            "apiKey": api_key  # Pass the secure token pulled from your local .env
        }
        
        try:
            # Execute HTTP GET request to the NVD API endpoint
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                return data
        except Exception as e:
            print(f"Error fetching data from NVD API: {e}")
        return None

    def ingest_greenbone_xml(self):
        """Extracts and normalizes raw vulnerabilities from an actual Greenbone XML file"""
        normalized_records = []
        
        if not os.path.exists(self.xml_path):
            print(f"Error: File not found at {self.xml_path}")
            return []

        tree = ET.parse(self.xml_path)
        root = tree.getroot()
        all_results = root.findall('.//result')
        
        for result in all_results:
            try:
                # 1. EXTRACT (Safely retrieve text values from XML tags)
                host_node = result.find('host') if result.find('host') is not None else result.find('.//host')
                raw_ip = host_node.text if host_node is not None else "0.0.0.0"
                
                port_node = result.find('port') if result.find('port') is not None else result.find('.//port')
                raw_port = port_node.text if port_node is not None else "0"
                
                cve_node = result.find('.//cve')
                raw_cve = cve_node.text if (cve_node is not None and cve_node.text) else "N/A"

                severity_node = result.find('.//nvt/cvss_base')
                raw_severity = severity_node.text if (severity_node is not None and severity_node.text) else "0.0"

                # 2. TRANSFORM & NORMALIZE (Cast plain strings to valid database types)
                port_candidate = raw_port.split('/') if '/' in raw_port else raw_port
                clean_port = int(port_candidate) if port_candidate.isdigit() else 0
                
                try:
                    clean_severity = float(raw_severity)
                except ValueError:
                    clean_severity = 0.0
                
                # 3. NVD API ENRICHMENT (Correlate with NIST Threat Intelligence)
                nvd_metadata = self.fetch_nvd_data(raw_cve.strip())
                
                clean_record = {
                    "target_host": str(raw_ip).strip(),
                    "target_port": clean_port,
                    "cve_id": str(raw_cve).strip(),
                    "base_severity": clean_severity,
                    "nvd_connected": True if nvd_metadata else False  # Verification flag for API status
                }
                
                normalized_records.append(clean_record)
                
            except Exception as e:
                print(f"Skipping a messy row due to parsing error: {e}")
                continue
                
        return normalized_records

if __name__ == "__main__":
    # Ingesting the real Greenbone scan report from scan_reports
    pipeline = SecurityDataPipeline('scan_reports/report-20b4791c-124e-4887-ac79-7034b0496569.xml', 'taxonomies_v1.json')
    results = pipeline.ingest_greenbone_xml()
    print(f"Successfully normalized {len(results)} vulnerability entries!")
    
    output_filename = "normalized_results.json"
    with open(output_filename, "w") as f:
        json.dump(results, f, indent=4)
    print(f"Saved clean dataset to {output_filename}")
