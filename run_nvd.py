import os
import requests
from dotenv import load_dotenv

load_dotenv()
api_key = os.getenv("NVD_API_KEY")

# The exact base URL for the entire v2.0 endpoint tree
BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

print("--- Testing NVD Base URL Integration ---")

headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Accept": "application/json"
}

if api_key:
    headers["apiKey"] = api_key.strip("'\" ")
    print("API key loaded successfully.")
else:
    print("Warning: Operating without an API Key.")

# Query parameters appended to the baseURL
params = {"resultsPerPage": 5}

try:
    session = requests.Session()
    session.trust_env = False

    # Calling the baseURL with parameters
    response = session.get(
        BASE_URL, 
        headers=headers, 
        params=params, 
        timeout=15
    )
    
    print(f"Server Status Code: {response.status_code}")
    print(f"Content-Type: {response.headers.get('Content-Type')}")
    
    if "application/json" in response.headers.get("Content-Type", ""):
        json_data = response.json()
        vulnerabilities = json_data.get("vulnerabilities", [])
        print("Success! Data package parsed safely from the Base URL.")
        print(f"Vulnerability Items Found: {len(vulnerabilities)}")
    else:
        print("Error: Server did not return JSON format.")
        print(f"Raw Output Snippet: {response.text[:200]}")

except Exception as e:
    print(f"Execution failed due to: {e}")
