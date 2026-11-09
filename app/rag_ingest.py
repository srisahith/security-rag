# import os
# import psycopg2
# from pgvector.psycopg2 import register_vector
# from ollama import Client

# OLLAMA_HOST = os.getenv("OLLAMA_URL", "http://host.docker.internal:11434")
# client = Client(host=OLLAMA_HOST)

# DB_URL = os.getenv("DATABASE_URL")
# conn = psycopg2.connect(DB_URL)
# cur = conn.cursor()

# # 1. Enable vector extension and create table
# cur.execute("CREATE EXTENSION IF NOT EXISTS vector;")
# cur.execute("CREATE TABLE IF NOT EXISTS cve_knowledge (id SERIAL PRIMARY KEY, content TEXT, embedding vector(768));")
# register_vector(conn)

# # 2. Read the text file we just created
# print("[RAG] Reading cve_data.txt...")
# with open("cve_data.txt", "r") as file:
#     # Read line by line, ignoring empty lines
#     threat_intel = [line.strip() for line in file if line.strip()]

# # 3. Generate embeddings and store in Postgres
# print(f"[RAG] Ingesting {len(threat_intel)} threat intel items...")
# for text in threat_intel:
#     response = client.embeddings(model="nomic-embed-text", prompt=text)
#     embedding = response["embedding"]
    
#     cur.execute("INSERT INTO cve_knowledge (content, embedding) VALUES (%s, %s)", (text, embedding))
    
# conn.commit()
# cur.close()
# conn.close()
# print("[RAG] Threat Intel successfully stored in pgvector!")

import os
import psycopg2
from pgvector.psycopg2 import register_vector
from ollama import Client
from langchain_experimental.text_splitter import SemanticChunker
from langchain_community.embeddings import OllamaEmbeddings

OLLAMA_HOST = os.getenv("OLLAMA_URL", "http://host.docker.internal:11434")
client = Client(host=OLLAMA_HOST)

DB_URL = os.getenv("DATABASE_URL")
conn = psycopg2.connect(DB_URL)
cur = conn.cursor()

# Setup Tables (if not exists)
cur.execute("CREATE EXTENSION IF NOT EXISTS vector;")
cur.execute("CREATE TABLE IF NOT EXISTS raw_intel (id SERIAL PRIMARY KEY, content TEXT, embedding vector(768));")
register_vector(conn)

# Setup Semantic Chunker
embeddings = OllamaEmbeddings(model="nomic-embed-text", base_url=OLLAMA_HOST)
semantic_splitter = SemanticChunker(embeddings, breakpoint_threshold_type="percentile")

# Read the RAW text
print("[RAW RAG] Reading raw_threat_intel.txt...")
with open("raw_threat_intel.txt", "r") as file:
    raw_text = file.read()

print("[RAW RAG] Splitting messy text into semantic chunks...")
# Because the text is rough, the semantic splitter will find the logical breaks
chunks = semantic_splitter.split_text(raw_text)

print(f"[RAW RAG] Created {len(chunks)} semantic chunks.")

for chunk in chunks:
    if len(chunk) < 20: continue # Ignore tiny garbage chunks
    response = client.embeddings(model="nomic-embed-text", prompt=chunk)
    embedding = response["embedding"]
    
    cur.execute("INSERT INTO raw_intel (content, embedding) VALUES (%s, %s)", (chunk, embedding))

conn.commit()
cur.close()
conn.close()
print("[RAW RAG] Messy data successfully chunked and stored!")