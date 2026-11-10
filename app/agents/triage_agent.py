import json
from ollama import Client
import os

client = Client(host=os.getenv("OLLAMA_URL", "http://host.docker.internal:11434"))

def triage_agent(question: str):
    """
    LLM-based intent classification.
    Returns a JSON dict: {"needs_search": bool, "needs_remediation": bool}
    """
    prompt = f"""You are a SOC Triage Agent. Analyze this user question: "{question}"
    
    DEFAULT POLICY:
    - ALWAYS set needs_remediation to true.
    - ONLY set needs_remediation to false if the user EXPLICITLY says they do NOT want a fix (e.g., "just tell me what it is", "no fix needed", "don't give me remediation").
    
    SEARCH POLICY:
    - Set needs_search to true for ANY question about a vulnerability, CVE, VDB, or threat.
    
    Reply ONLY with valid JSON:
    {{"needs_search": true/false, "needs_remediation": true/false}}"""
    
    try:
        response = client.chat(
            model="qwen2.5:1.5b",
            messages=[{"role": "user", "content": prompt}],
            format="json"
        )
        return json.loads(response['message']['content'])
    except Exception as e:
        print(f"[TRIAGE AGENT ERROR] {e}")
        # Fallback: always do both
        return {"needs_search": True, "needs_remediation": True}