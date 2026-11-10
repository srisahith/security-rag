import json
from ollama import Client
import os

client = Client(host=os.getenv("OLLAMA_URL", "http://host.docker.internal:11434"))

def triage_agent(question: str):
    prompt = f"""You are a SOC Triage Agent. Analyze this user question: "{question}"
    
    RULES:
    1. If the user asks about ANY vulnerability, CVE, VDB, vendor, product, or threat intel, you MUST set needs_search to true.
    2. If the user asks for a fix, patch, remediation, mitigation, or "how to fix", you MUST set needs_remediation to true.
    3. If the question contains an ID like CVE-2024-1234 or VDB-249838, set both needs_search and needs_remediation to true.
    
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
        print(f"[TRIAGE ERROR] {e}")
        return {"needs_search": True, "needs_remediation": True} # Fallback: do both