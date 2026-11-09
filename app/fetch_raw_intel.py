import httpx
from bs4 import BeautifulSoup

# A real CISA page with raw, unstructured text about threats
URL = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"

def fetch_raw_text():
    print(f"[RAW RAG] Scraping unstructured text from {URL}...")
    try:
        response = httpx.get(URL, timeout=30)
        response.raise_for_status()
        
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Extract ONLY the raw, visible text (stripping all HTML tags)
        # This is messy. It has no JSON structure.
        raw_text = soup.get_text(separator=' ', strip=True)
        
        # Save it as a raw text file
        with open("raw_threat_intel.txt", "w") as file:
            file.write(raw_text)
            
        print(f"[RAW RAG] Successfully saved {len(raw_text)} characters of messy text to raw_threat_intel.txt")
        
    except Exception as e:
        print(f"[RAW RAG] Failed to fetch: {e}")

if __name__ == "__main__":
    fetch_raw_text()