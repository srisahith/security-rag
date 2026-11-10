import os
from dotenv import load_dotenv

# 🚨 Load the .env file directly inside the MCP Server process
load_dotenv()

from mcp.server.fastmcp import FastMCP
import psycopg2
from pgvector.psycopg2 import register_vector
from ollama import Client
import re
# Initialize the MCP Server
mcp = FastMCP("ThreatIntelDB")
client = Client(host=os.getenv("OLLAMA_URL", "http://host.docker.internal:11434"))

def extract_ids(question: str) -> list[str]:
    """Universal ID Extractor (Zero LLM) for CVE, VDB, GHSA, etc."""
    found_ids = []
    clean_q = "".join([c if c.isalnum() else " " for c in question]).upper()
    tokens = clean_q.split()
    for i in range(len(tokens)):
        if tokens[i] in ["CVE", "VDB", "GHSA", "MSRC"]:
            if i + 2 < len(tokens):
                year, cid = tokens[i+1], tokens[i+2]
                if year.isdigit() and len(year) == 4 and cid.isdigit() and 4 <= len(cid) <= 7:
                    found_ids.append(f"{tokens[i]}-{year}-{cid}")
    return list(set(found_ids))

@mcp.tool()
def search_cve(question: str) -> str:
    """
    Search the local CISA/NVD threat intel database.
    Use this tool whenever the user asks about a vulnerability, CVE, VDB, or threat.
    """
    print(f"[MCP TOOL] Searching DB for: {question}")
    
    conn = psycopg2.connect(os.getenv("DATABASE_URL"))
    cur = conn.cursor()
    register_vector(conn)
    
    try:
        # 1. Extract IDs (CVE-2024-1234, VDB-249838, etc.)
        found_ids = extract_ids(question)
        print(f"[MCP TOOL] Extracted IDs: {found_ids}")
        
        # 2. Build SQL
        sql_query = "SELECT content FROM lake_children WHERE 1=1"
        params = []
        
        # 🚨 EXACT ID BOOSTING
        if found_ids:
            boost_conditions = " OR ".join(["content ILIKE %s"] * len(found_ids))
            sql_query += f" AND ({boost_conditions})"
            for cve in found_ids:
                params.append(f"%{cve}%")
        
        # 3. Vector Search
        query_embedding = client.embeddings(model="nomic-embed-text", prompt=question)["embedding"]
        sql_query += " ORDER BY embedding <=> %s::vector LIMIT 3;"
        params.append(query_embedding)
        
        cur.execute(sql_query, tuple(params))
        results = cur.fetchall()
        
        if not results:
            return "No relevant threat intel found in the database."
            
        # 4. Return context
        context = "\n\n---\n\n".join([row[0] for row in results])
        print(f"[MCP TOOL] Returning {len(results)} chunks to the agent.")
        return context
        
    except Exception as e:
        print(f"[MCP ERROR] {e}")
        return f"Database error: {e}"
    finally:
        cur.close()
        conn.close()

if __name__ == "__main__":
    print("Starting ThreatIntel MCP Server...")
    mcp.run()