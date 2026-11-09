import httpx
from bs4 import BeautifulSoup
import os
import datetime
import json
import zipfile
import io
import feedparser

LAKE_DIR = "data_lake"
os.makedirs(LAKE_DIR, exist_ok=True)

# 1. Unstructured HTML Sources (Scraped)
HTML_SOURCES = {
    "cisa_kev": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
    "the_hacker_news": "https://thehackernews.com/",
    "owasp_top_10": "https://owasp.org/www-project-top-ten/"
}

# 2. High-Volume RSS Feeds (Real-time Threat Intel)
RSS_SOURCES = {
    "bleepingcomputer": "https://www.bleepingcomputer.com/feed/",
    "krebsonsecurity": "https://krebsonsecurity.com/feed/",
    "cisco_talos": "https://blog.talosintelligence.com/rss/",
    "unit42": "https://unit42.paloaltonetworks.com/feed/?v=2"
}

# 3. Massive Structured Feed (NVD Bulk JSON)
NVD_YEAR = "2024" 

def fetch_html_sources():
    for source_name, url in HTML_SOURCES.items():
        print(f"[DATA LAKE] Scraping HTML: {source_name}...")
        try:
            response = httpx.get(url, timeout=30, follow_redirects=True)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, 'html.parser')
            
            for tag in soup(["script", "style", "nav", "footer", "header", "aside"]):
                tag.decompose()
            
            structural_elements = soup.find_all(['p', 'h1', 'h2', 'h3', 'li', 'td'])
            clean_lines = [el.get_text(separator=' ', strip=True) for el in structural_elements if len(el.get_text(strip=True)) > 30]
            raw_text = "\n\n".join(clean_lines)
            
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            file_path = os.path.join(LAKE_DIR, f"html_{source_name}_{timestamp}.txt")
            
            with open(file_path, "w", encoding="utf-8") as file:
                file.write(raw_text)
            print(f"  --> Saved {len(raw_text)} chars to {file_path}")
        except Exception as e:
            print(f"  --> Failed to scrape {source_name}: {e}")

def fetch_rss_sources():
    for source_name, url in RSS_SOURCES.items():
        print(f"[DATA LAKE] Fetching RSS: {source_name}...")
        try:
            # feedparser handles the XML parsing for us
            feed = feedparser.parse(url)
            clean_lines = []
            for entry in feed.entries:
                title = entry.get('title', 'No Title')
                summary = entry.get('summary', 'No Summary')
                clean_lines.append(f"Title: {title}\nSummary: {summary}")
                
            raw_text = "\n\n".join(clean_lines)
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            file_path = os.path.join(LAKE_DIR, f"rss_{source_name}_{timestamp}.txt")
            
            with open(file_path, "w", encoding="utf-8") as file:
                file.write(raw_text)
            print(f"  --> Saved {len(raw_text)} chars to {file_path}")
        except Exception as e:
            print(f"  --> Failed to fetch {source_name}: {e}")

def fetch_nvd_bulk(year=NVD_YEAR):
    print(f"[DATA LAKE] Downloading NVD bulk feed for {year} (This might take a minute)...")
    url = f"https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{year}.json.zip"
    
    try:
        response = httpx.get(url, timeout=120, follow_redirects=True)
        response.raise_for_status()
        
        with zipfile.ZipFile(io.BytesIO(response.content)) as z:
            json_filename = z.namelist()[0]
            with z.open(json_filename) as f:
                data = json.load(f)
                vulnerabilities = data.get("vulnerabilities", [])
                print(f"  --> Found {len(vulnerabilities)} CVEs in NVD {year}")
                
                clean_lines = []
                # Limit to 5000 to prevent crashing your 16GB laptop during ingestion
                for vuln in vulnerabilities[:100]: 
                    cve = vuln.get("cve", {})
                    cve_id = cve.get("id", "Unknown")
                    desc = cve.get("descriptions", [{}])[0].get("value", "No description")
                    clean_lines.append(f"CVE ID: {cve_id}. Description: {desc}")
                
                raw_text = "\n\n".join(clean_lines)
                timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                file_path = os.path.join(LAKE_DIR, f"json_nvd_{timestamp}.txt")
                
                with open(file_path, "w", encoding="utf-8") as file:
                    file.write(raw_text)
                print(f"  --> Saved {len(clean_lines)} CVEs to {file_path}")
                
    except Exception as e:
        print(f"  --> Failed to fetch NVD: {e}")

if __name__ == "__main__":
    print("🚀 Starting Massive Data Lake Ingestion...")
    fetch_html_sources()
    fetch_rss_sources()
    fetch_nvd_bulk()
    print("✅ Data Lake Ingestion Complete!")