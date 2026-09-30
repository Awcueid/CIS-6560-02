import os
import time
import requests
from dotenv import load_dotenv

# 1. Load environment variables from the local .env file
load_dotenv()
NVD_API_KEY = os.getenv("NVD_API_KEY")

# Official NVD API v2.0 endpoint URL
NVD_BASE_URL = "https://nist.gov"

def fetch_recent_cves(results_per_page=5):
    """
    Fetches the most recent CVEs from the official NVD API v2.0.
    """
    # 2. Build headers with the API Key if it exists
    headers = {}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY
        print("NVD API Key loaded successfully.")
    else:
        print("Warning: Operating without an API Key. Strict rate limits apply.")

    # 3. Parameters for pagination and limits
    params = {"resultsPerPage": results_per_page}

    try:
        # 4. Make the HTTP request
        response = requests.get(NVD_BASE_URL, headers=headers, params=params, timeout=15)
        
        # Debugging tools to see exactly what the server returned
        print(f"HTTP Status Code: {response.status_code}")
        
        # 5. Handle potential API status failures gracefully
        if response.status_code == 403:
            print("Error 403: Invalid API key, incorrect headers, or IP blocked.")
            print(f"Response Text snippet: {response.text[:200]}")
            return None
        elif response.status_code == 429:
            print("Error 429: Rate limit hit. Slow down your requests.")
            return None

        # Raise an exception for other bad status codes (e.g., 500, 404)
        response.raise_for_status()
        
        # 6. Parse JSON data
        data = response.json()
        print(f"Successfully fetched {len(data.get('vulnerabilities', []))} CVEs.")
        return data

    except requests.exceptions.JSONDecodeError:
        print("Crash prevented: Received invalid data format (HTML instead of JSON).")
        print(f"Server responded with: {response.text[:200]}")
        return None
    except requests.exceptions.RequestException as e:
        print(f"Network error occurred: {e}")
        return None

if __name__ == "__main__":
    print("Starting NVD API Data Extraction Test...")
    fetch_recent_cves(results_per_page=5)
    
    # Mandatory sleep delay to protect your IP from rate limits
    time.sleep(0.6)
