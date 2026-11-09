import os
import re
import json
import redis
import psycopg2
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from pgvector.psycopg2 import register_vector
from ollama import Client
from flashrank import Ranker, RerankRequest

# --- 1. OBSERVABILITY IMPORTS ---
from prometheus_fastapi_instrumentator import Instrumentator
from langfuse import Langfuse

# --- 2. CELERY IMPORTS ---
from app.workers import process_data_lake_task

# --- 3. SETUP ---
app = FastAPI(title="Aegis-Sentinel API")
Instrumentator().instrument(app).expose(app)

# Initialize Langfuse (v2 syntax for your v2.95.11 server)
langfuse = Langfuse()

# Initialize Redis for Caching
redis_client = redis.Redis.from_url(os.getenv("REDIS_URL", "redis://redis:6379/0"))

# --- 4. AI CLIENTS SETUP ---
OLLAMA_HOST = os.getenv("OLLAMA_URL", "http://host.docker.internal:11434")
client = Client(host=OLLAMA_HOST)

print("[RERANK] Loading FlashRank model...")
ranker = Ranker(model_name="ms-marco-MiniLM-L-12-v2", cache_dir="/tmp")

# --- 5. REQUEST MODELS ---
class RAGRequest(BaseModel):
    question: str
    source_filter: str | None = None
    days_back: int | None = None

# --- 6. MULTI-LAYER CVE EXTRACTOR ---
def extract_cve_ids(question: str) -> list[str]:
    found_cves = []
    # Aggressive Normalization: Uppercase, replace non-alphanumeric with spaces
    clean_q = "".join([c if c.isalnum() else " " for c in question]).upper()
    tokens = clean_q.split()
    
    for i in range(len(tokens)):
        if tokens[i] == "CVE":
            if i + 2 < len(tokens):
                year, cid = tokens[i+1], tokens[i+2]
                if year.isdigit() and len(year) == 4 and cid.isdigit() and 4 <= len(cid) <= 7:
                    found_cves.append(f"CVE-{year}-{cid}")
            elif i + 1 < len(tokens):
                next_token = tokens[i+1]
                if len(next_token) >= 8 and next_token[:4].isdigit() and next_token[4:].isdigit():
                    found_cves.append(f"CVE-{next_token[:4]}-{next_token[4:]}")
                    
    # Fallback for bare numbers (e.g., 2024-0293) if "CVE" is missing
    if not found_cves and "CVE" not in clean_q:
        for i in range(len(tokens) - 1):
            if tokens[i].isdigit() and len(tokens[i]) == 4 and tokens[i+1].isdigit() and 4 <= len(tokens[i+1]) <= 7:
                if 2000 <= int(tokens[i]) <= 2030:
                    found_cves.append(f"CVE-{tokens[i]}-{tokens[i+1]}")
                    
    return list(set(found_cves))

# --- 7. API ENDPOINTS ---

@app.post("/api/ingest")
def trigger_ingestion():
    task = process_data_lake_task.delay()
    return {"message": "Ingestion started in background", "task_id": task.id}

@app.post("/api/ask")
def ask_threat_intel(request: RAGRequest):
    # 1. CHECK REDIS CACHE
    cache_key = f"rag:{request.question}:{request.source_filter}:{request.days_back}"
    cached_result = redis_client.get(cache_key)
    if cached_result:
        return json.loads(cached_result)

    # 2. START LANGFUSE TRACE
    trace = langfuse.trace(name="RAG_Query", input={"question": request.question})
    
    conn = psycopg2.connect(os.getenv("DATABASE_URL"))
    cur = conn.cursor()
    register_vector(conn)
    
    try:
        # 3. Extract CVEs
        found_cves = extract_cve_ids(request.question)
        
        # 4. BUILD BASE SQL
        sql_query = "SELECT content FROM lake_children WHERE 1=1"
        params = []
        
        if request.source_filter:
            sql_query += " AND source = %s "
            params.append(request.source_filter)
            
        if request.days_back:
            sql_query += f" AND created_at >= NOW() - INTERVAL '{request.days_back} days' "

        # 🚨 5. BRANCH 1: EXACT CVE MATCH (Direct DB Return, No LLM)
        if found_cves:
            boost_conditions = " OR ".join(["content ILIKE %s"] * len(found_cves))
            sql_query += f" AND ({boost_conditions}) LIMIT 1;"
            
            for cve in found_cves:
                params.append(f"%{cve}%")
                
            cur.execute(sql_query, tuple(params))
            exact_match = cur.fetchone()
            
            if exact_match:
                context = exact_match[0]
                # Clean up the enrichment header for a nicer output
                final_answer = context.replace("[Source: NVD] ", "").strip()
                
                response_data = {
                    "question": request.question,
                    "answer_type": "Exact CVE Match (Database)",
                    "context_snippet": context[:300] + "...",
                    "ai_answer": final_answer
                }
                redis_client.setex(cache_key, 3600, json.dumps(response_data))
                langfuse.flush()
                return response_data

        # 🚨 6. BRANCH 2: CONCEPTUAL QUERY (Vector Search + LLM Reasoning)
        query_embedding = client.embeddings(model="nomic-embed-text", prompt=request.question)["embedding"]
        
        # Rebuild query for vector search
        sql_query = "SELECT content FROM lake_children WHERE 1=1"
        params = []
        
        if request.source_filter:
            sql_query += " AND source = %s "
            params.append(request.source_filter)
            
        if request.days_back:
            sql_query += f" AND created_at >= NOW() - INTERVAL '{request.days_back} days' "
            
        sql_query += " ORDER BY embedding <=> %s::vector LIMIT 5;"
        params.append(query_embedding)
        
        cur.execute(sql_query, tuple(params))
        results = cur.fetchall()
        
        if not results:
            context = "No relevant threat intel found."
        else:
            # Rerank for better precision
            passages = [{"id": i, "text": row[0]} for i, row in enumerate(results)]
            rerank_request = RerankRequest(query=request.question, passages=passages)
            reranked_results = ranker.rerank(rerank_request)
            
            # Take top 3 chunks
            top_chunks = [res["text"] for res in reranked_results[:3]]
            context = "\n\n---\n\n".join(top_chunks)

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {e}")
    finally:
        cur.close()
        conn.close()

    # 7. LLM REASONING (Only for conceptual queries)
    system_prompt = f"""You are an expert Cyber Security Analyst AI. 
    You have been given raw threat intelligence data. Your job is to analyze it and answer the user's question.
    
    RAW DATA FROM DATABASE:
    {context}
    
    INSTRUCTIONS:
    - Answer the question using ONLY the raw data provided.
    - If the user asks to compare vulnerabilities, identify the differences in severity or impact.
    - If the user asks for a remediation plan, generate a step-by-step fix based on the descriptions.
    - If the answer is not in the data, say "I don't know based on the current threat intel."
    - Do NOT just repeat the raw data. Synthesize it into a clear, professional answer.
    """
    
    try:
        response = client.chat(
            model="qwen2.5:1.5b",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": request.question}
            ]
        )
        answer = response['message']['content'].strip()
        
        generation = trace.generation(
            name="LLM_Reasoning",
            model="qwen2.5:1.5b",
            input=system_prompt,
            output=answer
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"LLM error: {e}")

    # 8. SAVE TO CACHE
    response_data = {
        "question": request.question,
        "source_filter": request.source_filter or "All Sources",
        "days_back": request.days_back or "All Time",
        "answer_type": "LLM Reasoning (RAG)",
        "context_snippet": context[:300] + "...",
        "ai_answer": answer
    }
    redis_client.setex(cache_key, 3600, json.dumps(response_data))
    langfuse.flush()

    return response_data

@app.post("/api/scan")
def start_scan(target_url: str):
    from app.workers import trigger_dast_scan
    task = trigger_dast_scan.delay(target_url)
    return {"message": "DAST scan started in the background", "task_id": task.id}

@app.get("/")
def read_root():
    return {"status": "Aegis-Sentinel is running", "system": "AI DAST + IRIS + Hybrid RAG"}