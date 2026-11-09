import httpx
import json

# The official CISA KEV JSON feed URL
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

def fetch_cisa_kev():
    print("[RAG] Fetching live CISA KEV data...")
    try:
        response = httpx.get(CISA_KEV_URL, timeout=30)
        response.raise_for_status()
        data = response.json()
        
        vulnerabilities = data.get("vulnerabilities", [])
        print(f"[RAG] Found {len(vulnerabilities)} known exploited vulnerabilities.")
        
        # Write to our text file in a format the RAG agent understands
        with open("cve_data.txt", "w") as file:
            for vuln in vulnerabilities[:7000]: # Limit to 50 to keep it fast locally
                cve_id = vuln.get("cveID", "Unknown")
                vendor = vuln.get("vendorProject", "Unknown")
                product = vuln.get("product", "Unknown")
                desc = vuln.get("shortDescription", "No description")
                action = vuln.get("requiredAction", "No action specified")
                
                # Format it as a single line of text
                line = f"{cve_id} ({vendor} {product}): {desc}. Required Action: {action}\n"
                file.write(line)
                
        print("[RAG] Successfully saved live CVE data to cve_data.txt")
        
    except Exception as e:
        print(f"[RAG] Failed to fetch live data: {e}")

if __name__ == "__main__":
    fetch_cisa_kev()