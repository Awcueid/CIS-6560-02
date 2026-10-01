import xml.etree.ElementTree as ET
import json
import os

class SecurityDataPipeline:
    def __init__(self, xml_path, taxonomy_path):
        self.xml_path = xml_path
        self.taxonomy_path = taxonomy_path
        
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
                # 1. EXTRACT
                host_node = result.find('host') if result.find('host') is not None else result.find('.//host')
                raw_ip = host_node.text if host_node is not None else "0.0.0.0"
                
                port_node = result.find('port') if result.find('port') is not None else result.find('.//port')
                raw_port = port_node.text if port_node is not None else "0"
                
                cve_node = result.find('.//cve')
                raw_cve = cve_node.text if (cve_node is not None and cve_node.text) else "N/A"
                if raw_cve == "N/A" or not raw_cve.strip():
                    nvt_node = result.find('.//nvt')
                    if nvt_node is not None and 'cve' in nvt_node.attrib:
                        raw_cve = nvt_node.attrib['cve']

                severity_node = result.find('.//nvt/cvss_base')
                if severity_node is None:
                    severity_node = result.find('.//severity')
                raw_severity = severity_node.text if (severity_node is not None and severity_node.text) else "0.0"

                # 2. TRANSFORM & NORMALIZE
                port_candidate = raw_port.split('/')[0] if '/' in raw_port else raw_port
                clean_port = int(port_candidate) if port_candidate.isdigit() else 0
                
                try:
                    clean_severity = float(raw_severity)
                except ValueError:
                    clean_severity = 0.0
                
                clean_record = {
                    "target_host": str(raw_ip).strip(),
                    "target_port": clean_port,
                    "cve_id": str(raw_cve).strip(),
                    "base_severity": clean_severity
                }
                
                normalized_records.append(clean_record)
                
            except Exception as e:
                print(f"Skipping a messy row due to parsing error: {e}")
                continue
                
        return normalized_records

if __name__ == "__main__":
    pipeline = SecurityDataPipeline('scan_reports/report-ead145e5-f0a6-494c-8b37-09a9b59c7d94.xml', 'taxonomies_v1.json')
    results = pipeline.ingest_greenbone_xml()
    print(f"Successfully normalized {len(results)} vulnerability entries!")
    
    # SAVE TO A JSON FILE FOR EASY VIEWING
    output_filename = "normalized_results.json"
    with open(output_filename, "w") as f:
        json.dump(results, f, indent=4)
    print(f"Saved clean dataset to {output_filename}")
