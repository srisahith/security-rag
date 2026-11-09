import httpx
from bs4 import BeautifulSoup
from ollama import Client
import os
from app.database import SessionLocal, ScanRecord

OLLAMA_HOST = os.getenv("OLLAMA_URL", "http://host.docker.internal:11434")
client = Client(host=OLLAMA_HOST)

def test_sqli(url: str, payload: str):
    try:
        response = httpx.get(f"{url}?id={payload}", timeout=5)
        sql_errors = ["SQL syntax", "MySQL", "ORA-", "PostgreSQL"]
        if any(error in response.text for error in sql_errors):
            return True
        return False
    except Exception as e:
        print(f"Request failed: {e}")
        return False

# def run_ai_dast_scan(target_url: str):
#     print(f"[DAST] Starting AI scan on {target_url}")
    
#     try:
#         res = httpx.get(target_url, timeout=5)
#         soup = BeautifulSoup(res.text, 'html.parser')
#         print(f"[DAST] Successfully fetched page.")
#     except Exception as e:
#         return f"Failed to reach target: {e}"

#     system_prompt = "You are a DAST security scanner. Generate a raw SQL injection payload. Reply ONLY with the payload string. Do NOT use markdown, code blocks, backticks, or newlines."
#     user_prompt = f"Target: {target_url}. Generate a payload to test the 'id' parameter."
    
#     # 1. Set a default fallback payload first
#     payload = "1' OR '1'='1"
    
#     # 2. Ask the AI for a better one
#     try:
#         response = client.chat(
#             model="qwen2.5:1.5b",
#             messages=[
#                 {"role": "system", "content": system_prompt},
#                 {"role": "user", "content": user_prompt}
#             ]
#         )
        
#         raw_payload = response['message']['content'].strip()
#         # Clean the payload (remove markdown backticks and newlines)
#         payload = raw_payload.replace('```sql', '').replace('```', '').replace('\n', ' ').strip()
#         print(f"[DAST] AI generated payload: {payload}")
#     except Exception as e:
#         print(f"[DAST] Ollama connection failed, using fallback payload. Error: {e}")

#     # 3. Test the payload against the target
#     # is_vulnerable = test_sqli(target_url, payload)
#     is_vulnerable = True
#     status_message = "Vulnerability Found" if is_vulnerable else "Scan Complete - No Vulnerability"
    
#     # 4. Save the activity to PostgreSQL
#     db = SessionLocal()
#     try:
#         new_record = ScanRecord(
#             target_url=target_url,
#             payload_used=payload,
#             status=status_message
#         )
#         db.add(new_record)
#         db.commit()
#         print(f"[POSTGRES] 📝 Saved scan record to database. Status: {status_message}")
#     except Exception as e:
#         print(f"[POSTGRES] Error saving record: {e}")
#     finally:
#         db.close()

#     # 5. Trigger IRIS if a vulnerability was found
#     if is_vulnerable:
#         print("[DAST] 🚨 Vulnerability Found! Sending event to IRIS...")
#         from app.workers import trigger_iris_lockdown
#         trigger_iris_lockdown.delay("192.168.1.50", payload)
    
#     return status_message
import psycopg2
from pgvector.psycopg2 import register_vector

def get_threat_intel(query: str):
    """Uses RAG to find the most relevant CVE for the target."""
    conn = psycopg2.connect(os.getenv("DATABASE_URL"))
    cur = conn.cursor()
    register_vector(conn)
    
    # 1. Turn the target URL into an embedding
    query_embedding = client.embeddings(model="nomic-embed-text", prompt=query)["embedding"]
    
    # 2. Find the closest matching CVE in Postgres (Cosine distance)
    cur.execute("""
        SELECT content FROM cve_knowledge 
        ORDER BY embedding <=> %s::vector LIMIT 1;
    """, (query_embedding,))
    
    result = cur.fetchone()
    cur.close()
    conn.close()
    
    return result[0] if result else "No specific CVE found."

def run_ai_dast_scan(target_url: str):
    print(f"[DAST] Starting AI scan on {target_url}")
    
    try:
        res = httpx.get(target_url, timeout=5)
        soup = BeautifulSoup(res.text, 'html.parser')
        print(f"[DAST] Successfully fetched page.")
    except Exception as e:
        return f"Failed to reach target: {e}"

    # 🚨 NEW: RAG RETRIEVAL
    print(f"[RAG] Searching Threat Intel for: {target_url}")
    context = get_threat_intel(target_url)
    print(f"[RAG] Retrieved Context: {context[:100]}...") # Print first 100 chars

    # 🚨 NEW: INJECT CONTEXT INTO SYSTEM PROMPT
    system_prompt = f"""You are a DAST security scanner. 
    Use this Threat Intel context to generate a specific SQL injection payload: {context}
    Reply ONLY with the payload string. Do NOT use markdown or backticks."""
    
    user_prompt = f"Target: {target_url}. Generate a payload."
    
    payload = "1' OR '1'='1" # Fallback
    
    try:
        response = client.chat(
            model="qwen2.5:1.5b",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ]
        )
        
        raw_payload = response['message']['content'].strip()
        payload = raw_payload.replace('```sql', '').replace('```', '').replace('\n', ' ').strip()
        print(f"[DAST] AI generated payload based on Threat Intel: {payload}")
    except Exception as e:
        print(f"[DAST] Ollama connection failed. Error: {e}")

    # Test and Save (Keep your existing code here)
    is_vulnerable = test_sqli(target_url, payload)
    status_message = "Vulnerability Found" if is_vulnerable else "Scan Complete - No Vulnerability"
    
    db = SessionLocal()
    try:
        new_record = ScanRecord(target_url=target_url, payload_used=payload, status=status_message)
        db.add(new_record)
        db.commit()
        print(f"[POSTGRES] 📝 Saved scan record. Status: {status_message}")
    except Exception as e:
        print(f"[POSTGRES] Error saving record: {e}")
    finally:
        db.close()

    if is_vulnerable:
        print("[DAST] 🚨 Vulnerability Found! Sending event to IRIS...")
        from app.workers import trigger_iris_lockdown
        trigger_iris_lockdown.delay("192.168.1.50", payload)
    
    return status_message