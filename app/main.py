import os
import re
import json
import redis
import psycopg2
from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from pgvector.psycopg2 import register_vector
from ollama import Client
from flashrank import Ranker, RerankRequest
from jose import JWTError, jwt
from passlib.context import CryptContext
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from datetime import datetime, timedelta

# --- 1. OBSERVABILITY & CELERY ---
from prometheus_fastapi_instrumentator import Instrumentator
from langfuse import Langfuse
from app.workers import process_data_lake_task
from app.agents.soc_agents import triage_agent, remediation_agent

# --- 2. SETUP ---
SECRET_KEY = "super-secret-aegis-key-change-in-prod"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

app = FastAPI(title="Aegis-Sentinel API")
Instrumentator().instrument(app).expose(app)
langfuse = Langfuse()

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

redis_client = redis.Redis.from_url(os.getenv("REDIS_URL", "redis://redis:6379/0"))

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/token")

# 🚨 TEMPORARY PLAIN-TEXT USER (Bypasses bcrypt issues for testing)
fake_users_db = {
    "admin": {
        "username": "admin",
        "password": "password123", 
    }
}

# AI Clients
OLLAMA_HOST = os.getenv("OLLAMA_URL", "http://host.docker.internal:11434")
client = Client(host=OLLAMA_HOST)
ranker = Ranker(model_name="ms-marco-MiniLM-L-12-v2", cache_dir="/tmp")

# --- 3. REQUEST MODELS ---
class RAGRequest(BaseModel):
    question: str
    source_filter: str | None = None
    days_back: int | None = None

# --- 4. AUTH HELPERS ---
def verify_password(plain_password, stored_password):
    return plain_password == stored_password

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=401, detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        return username
    except JWTError:
        raise credentials_exception

# --- 5. ENDPOINTS ---

@app.post("/api/token")
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = fake_users_db.get(form_data.username)
    if not user or not verify_password(form_data.password, user["password"]):
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    access_token = create_access_token(data={"sub": user["username"]})
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/api/ingest")
def trigger_ingestion(current_user: str = Depends(get_current_user)):
    task = process_data_lake_task.delay()
    return {"message": "Ingestion started", "task_id": task.id}

@app.post("/api/ask")
@limiter.limit("10/minute")
def ask_threat_intel(request: Request, rag_request: RAGRequest, current_user: str = Depends(get_current_user)):
    cache_key = f"rag:{rag_request.question}:{rag_request.source_filter}:{rag_request.days_back}"
    cached_result = redis_client.get(cache_key)
    if cached_result:
        return json.loads(cached_result)

    trace = langfuse.trace(name="RAG_Query", input={"question": rag_request.question})
    conn = psycopg2.connect(os.getenv("DATABASE_URL"))
    cur = conn.cursor()
    register_vector(conn)
    
    try:
        # 🚨 1. CLEAN THE QUERY (Remove fluff, keep alphanumeric and hyphens)
        clean_query = re.sub(r'[^A-Za-z0-9\-]', ' ', rag_request.question).strip()
        
        # 🚨 2. BUILD SQL
        sql_query = "SELECT content FROM lake_children WHERE 1=1"
        params = []
        
        if rag_request.source_filter:
            sql_query += " AND source = %s "
            params.append(rag_request.source_filter)
            
        if rag_request.days_back:
            sql_query += f" AND created_at >= NOW() - INTERVAL '{rag_request.days_back} days' "
            
        # 🚨 3. EXACT MATCH BYPASS (If the query has a hyphen and a number, it's an ID)
        if "-" in clean_query and any(char.isdigit() for char in clean_query):
            sql_query += " AND content ILIKE %s "
            params.append(f"%{clean_query}%")
            
        # 🚨 4. Add Vector Search as fallback
        query_embedding = client.embeddings(model="nomic-embed-text", prompt=rag_request.question)["embedding"]
        sql_query += " ORDER BY embedding <=> %s::vector LIMIT 3;"
        params.append(query_embedding)
        
        cur.execute(sql_query, tuple(params))
        results = cur.fetchall()
        
        if not results:
            context = "No relevant threat intel found."
        else:
            context = "\n\n---\n\n".join([row[0] for row in results])

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"DB error: {e}")
    finally:
        cur.close()
        conn.close()

    # 5. LLM Reasoning
    system_prompt = f"""You are a Cyber Security AI. Answer using ONLY this context: {context}"""
    try:
        response = client.chat(
            model="qwen2.5:1.5b",
            messages=[{"role": "system", "content": system_prompt}, {"role": "user", "content": rag_request.question}]
        )
        answer = response['message']['content'].strip()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"LLM error: {e}")

    response_data = {
        "question": rag_request.question,
        "answer_type": "LLM Reasoning",
        "context_snippet": context[:300] + "...",
        "ai_answer": answer
    }
    redis_client.setex(cache_key, 3600, json.dumps(response_data))
    langfuse.flush()
    return response_data

@app.post("/api/agent")
@limiter.limit("5/minute")
def agentic_workflow(request: Request, rag_request: RAGRequest, current_user: str = Depends(get_current_user)):
    trace = langfuse.trace(name="Multi_Agent_Workflow", input={"question": rag_request.question})
    
    # 1. Triage Agent
    decision = triage_agent(rag_request.question)
    print(f"[AGENT] Triage Decision: {decision}")
    trace.span(name="Triage_Agent", output=json.dumps(decision)).end()
    
    context = "No threat intel requested."
    remediation_plan = "No remediation requested."
    
    # 2. Threat Intel Agent (SQL Search)
        # 2. Threat Intel Agent (SQL Search)
        # 2. Threat Intel Agent (SQL Search)
    if decision.get("needs_search", True):
        print(f"[AGENT] Performing SQL search for: {rag_request.question}")
        conn = psycopg2.connect(os.getenv("DATABASE_URL"))
        cur = conn.cursor()
        register_vector(conn)
        try:
            # 🚨 1. Extract just the ID using a simple split
            # This handles "what is VDB-249838" -> "VDB-249838"
            clean_query = ""
            for word in rag_request.question.split():
                if "-" in word and any(char.isdigit() for char in word):
                    clean_query = word.strip("?.,;:")
                    break
            
            if not clean_query:
                # If no ID found, just use the whole question for vector search
                clean_query = rag_request.question
                
            print(f"[AGENT] Clean query: {clean_query}")
            
            # 🚨 2. Build the SQL
            sql_query = "SELECT content FROM lake_children WHERE 1=1"
            params = []
            
            if rag_request.source_filter:
                sql_query += " AND source = %s "
                params.append(rag_request.source_filter)
                
            # 🚨 3. If it looks like an ID, force the exact match
            if "-" in clean_query and any(char.isdigit() for char in clean_query):
                sql_query += " AND content ILIKE %s "
                params.append(f"%{clean_query}%")
                print(f"[AGENT] Added ILIKE filter: %{clean_query}%")
                
            # 🚨 4. Add the vector search
            query_embedding = client.embeddings(model="nomic-embed-text", prompt=rag_request.question)["embedding"]
            sql_query += " ORDER BY embedding <=> %s::vector LIMIT 3;"
            params.append(query_embedding)
            
            print(f"[AGENT] SQL: {sql_query}")
            cur.execute(sql_query, tuple(params))
            results = cur.fetchall()
            print(f"[AGENT] Found {len(results)} results.")
            
            if results:
                context = "\n\n---\n\n".join([row[0] for row in results])
            else:
                context = "No results found in database for this query."
                
        except Exception as e:
            print(f"[AGENT ERROR] {e}")
            context = f"Database error: {e}"
        finally:
            cur.close()
            conn.close()
    # 3. Remediation Agent
    if decision.get("needs_remediation", False) and context != "No threat intel requested.":
        remediation_plan = remediation_agent(context)
        trace.span(name="Remediation_Agent", output=remediation_plan[:500]).end()

    # 4. Final Synthesis
    final_answer = f"### Threat Intel Analysis\n{context}\n\n### Remediation Plan\n{remediation_plan}"
    
    langfuse.flush()
    
    return {
        "question": rag_request.question,
        "triage_decision": decision,
        "context_snippet": context[:300] + "...",
        "remediation_plan": remediation_plan,
        "ai_answer": final_answer
    }

@app.get("/")
def read_root():
    return {"status": "Aegis-Sentinel is running", "system": "Multi-Agent RAG + MCP Ready"}