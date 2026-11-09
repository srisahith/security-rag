import os
import psycopg2
import hashlib
import json
from pgvector.psycopg2 import register_vector
from ollama import Client
from langchain_text_splitters import RecursiveCharacterTextSplitter
import re

OLLAMA_HOST = os.getenv("OLLAMA_URL", "http://host.docker.internal:11434")
client = Client(host=OLLAMA_HOST)

DB_URL = os.getenv("DATABASE_URL")
conn = psycopg2.connect(DB_URL)
cur = conn.cursor()

# Setup Tables
cur.execute("CREATE EXTENSION IF NOT EXISTS vector;")
cur.execute("""
    CREATE TABLE IF NOT EXISTS lake_parents (
        id SERIAL PRIMARY KEY, 
        source TEXT, 
        full_text TEXT
    );
""")
cur.execute("""
    CREATE TABLE IF NOT EXISTS lake_children (
        id SERIAL PRIMARY KEY, 
        parent_id INTEGER REFERENCES lake_parents(id), 
        source TEXT, 
        content TEXT, 
        embedding vector(768),
        content_hash VARCHAR(64) UNIQUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
""")
register_vector(conn)

# Setup Safe Fallback Splitter (for massive HTML pages)
safe_splitter = RecursiveCharacterTextSplitter(
    chunk_size=1000, 
    chunk_overlap=150,
    separators=["\n\n", "\n", ". ", " ", ""]
)

LAKE_DIR = "data_lake"
files = [f for f in os.listdir(LAKE_DIR) if f.endswith('.txt')]

print(f"[PRODUCTION RAG] Processing {len(files)} files...")

for filename in files:
    file_path = os.path.join(LAKE_DIR, filename)
    
    # Determine source metadata
    if "cisa" in filename: source_name = "cisa"
    elif "hackernews" in filename: source_name = "hackernews"
    elif "owasp" in filename: source_name = "owasp"
    elif "bleepingcomputer" in filename: source_name = "bleepingcomputer"
    elif "krebsonsecurity" in filename: source_name = "krebsonsecurity"
    elif "cisco_talos" in filename: source_name = "cisco_talos"
    elif "unit42" in filename: source_name = "unit42"
    elif "nvd" in filename: source_name = "nvd"
    else: source_name = "unknown"
    
    with open(file_path, "r", encoding="utf-8") as file:
        raw_text = file.read()

    # Skip if already processed (File-level Hash)
    cur.execute("SELECT id FROM lake_parents WHERE full_text = %s", (raw_text,))
    if cur.fetchone():
        print(f"--> Skipping {filename} (Already processed)")
        continue

    print(f"--> Processing {filename} (Source: {source_name})...")

    cur.execute(
        "INSERT INTO lake_parents (source, full_text) VALUES (%s, %s) RETURNING id;", 
        (source_name, raw_text)
    )
    parent_id = cur.fetchone()[0]

    try:
        final_chunks = []

        # 🚨 1. DOCUMENT STRUCTURE-BASED CHUNKING (For NVD JSON)
        if "nvd" in filename:
            # We know the NVD file has a specific structure from fetch_lake.py
            # We split by the "CVE ID:" marker to keep records atomic
            raw_records = raw_text.split("CVE ID: ")
            for record in raw_records:
                if len(record.strip()) < 20: continue
                
                # 🚨 CONTEXTUAL ENRICHMENT: Extract exact CVE ID using Regex
                cve_match = re.search(r'CVE-\d{4}-\d{4,7}', record, re.IGNORECASE)
                cve_id = cve_match.group(0).upper() if cve_match else "Unknown CVE"
                
                enriched_chunk = f"[Source: NVD] [{cve_id}] CVE ID: {record.strip()}"
                final_chunks.append(enriched_chunk)

        # 🚨 2. RECURSIVE FALLBACK (For massive HTML/RSS feeds)
        else:
            # Split the HTML into manageable blocks
            blocks = safe_splitter.split_text(raw_text)
            for block in blocks:
                if len(block.strip()) < 50: continue
                
                # Contextual Enrichment: Prepend source
                enriched_chunk = f"[Source: {source_name}] {block.strip()}"
                final_chunks.append(enriched_chunk)

        print(f"    Created {len(final_chunks)} structured chunks.")

        # 🚨 3. EMBEDDING AND INSERTION
        inserted_count = 0
        for chunk in final_chunks:
            chunk_hash = hashlib.sha256(chunk.encode('utf-8')).hexdigest()
            
            # Check for duplicates
            cur.execute("SELECT id FROM lake_children WHERE content_hash = %s", (chunk_hash,))
            if cur.fetchone():
                continue 
            
            # Generate embedding
            response = client.embeddings(model="nomic-embed-text", prompt=chunk)
            embedding = response["embedding"]
            
            try:
                cur.execute(
                    "INSERT INTO lake_children (parent_id, source, content, embedding, content_hash) VALUES (%s, %s, %s, %s, %s)", 
                    (parent_id, source_name, chunk, embedding, chunk_hash)
                )
                inserted_count += 1
            except psycopg2.errors.UniqueViolation:
                conn.rollback()
                continue
            
        conn.commit()
        print(f"    ✅ Inserted {inserted_count} new enriched chunks.")
            
    except Exception as e:
        conn.rollback()
        print(f"    ❌ Failed to process {filename}: {e}")

cur.close()
conn.close()
print("[PRODUCTION RAG] Data Lake successfully updated!")