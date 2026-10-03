# Security Scan Report Verification Script # 

import os
import glob

REPORTS_DIR = "scan_reports"
search_path = os.path.join(REPORTS_DIR, "*.xml")
xml_files = glob.glob(search_path)

if not xml_files:
    print("No XML files found.")
else:
    target_file = xml_files[0]
    print(f"Inspecting file: {os.path.basename(target_file)}")
    print("-" * 50)
    
    try:
        with open(target_file, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        
        print(f"Total character length of file: {len(content)}")
        print("\n--- First 500 Characters of Raw Content ---")
        print(content[:500])
        print("-" * 50)
        
        # Check for common OpenVAS keywords
        keywords = ["result", "nvt", "severity", "threat", "cve", "vulnerability", "port"]
        print("\n--- Keyword Presence Check ---")
        for word in keywords:
            count = content.lower().count(word)
            print(f"Keyword '{word}': found {count} times")
            
    except Exception as e:
        print(f"Failed to read file: {e}")
