from mcp.server.fastmcp import FastMCP
import psycopg2
from pgvector.psycopg2 import register_vector
from ollama import Client
import os

# Initialize MCP Server
mcp = FastMCP("ThreatIntelDB")
client = Client(host=os.getenv("OLLAMA_URL", "http://host.docker.internal:11434"))

@mcp.tool()
def search_cve(question: str, source_filter: str = None) -> str:
    """
    Searches the local CISA/NVD database for cyber security vulnerabilities, 
    CVEs, and news using Hybrid Vector Search.
    """
    print(f"[MCP TOOL] Searching DB for: {question}")
    
    conn = psycopg2.connect(os.getenv("DATABASE_URL"))
    cur = conn.cursor()
    register_vector(conn)
    
    try:
        query_embedding = client.embeddings(model="nomic-embed-text", prompt=question)["embedding"]
        
        sql_query = """
            SELECT content, embedding <=> %s::vector as distance
            FROM lake_children
            WHERE 1=1
        """
        params = [query_embedding]
        
        if source_filter:
            sql_query += " AND source = %s "
            params.append(source_filter)
            
        sql_query += " ORDER BY distance ASC LIMIT 3;"
        
        cur.execute(sql_query, tuple(params))
        results = cur.fetchall()
        
        if not results:
            return "No relevant threat intel found in the database."
            
        # Combine top 3 chunks into a single context string
        context = "\n\n---\n\n".join([row[0] for row in results])
        return context
        
    except Exception as e:
        return f"Database error: {e}"
    finally:
        cur.close()
        conn.close()

if __name__ == "__main__":
    print("Starting ThreatIntel MCP Server...")
    mcp.run()