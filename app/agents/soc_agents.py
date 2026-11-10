import json
from ollama import Client
import os

OLLAMA_HOST = os.getenv("OLLAMA_URL", "http://host.docker.internal:11434")
client = Client(host=OLLAMA_HOST)
def triage_agent(question: str):
    prompt = f"""You are a SOC Triage Agent. Analyze this user question: "{question}"
    
    RULES:
    1. If the user asks about ANY vulnerability, CVE, VDB, vendor, product, or threat intel, you MUST set needs_search to true.
    2. If the user asks for a fix, patch, remediation, mitigation, solution, or "how to fix", you MUST set needs_remediation to true.
    3. If the user asks "how do I fix" or "how to remediate", set both needs_search and needs_remediation to true.
    
    Examples:
    - "What is CVE-2024-1234?" -> {{"needs_search": true, "needs_remediation": false}}
    - "How do I fix VDB-249838?" -> {{"needs_search": true, "needs_remediation": true}}
    - "Tell me about the Apache vulnerability" -> {{"needs_search": true, "needs_remediation": false}}
    - "Hello" -> {{"needs_search": false, "needs_remediation": false}}
    
    Reply ONLY with valid JSON:
    {{"needs_search": true/false, "needs_remediation": true/false}}"""
    
    try:
        response = client.chat(
            model="qwen2.5:1.5b",
            messages=[{"role": "user", "content": prompt}],
            format="json"
        )
        decision = json.loads(response['message']['content'])
        return decision
    except Exception as e:
        print(f"[TRIAGE ERROR] {e}")
        return {"needs_search": True, "needs_remediation": True} # Fallback: do both
def remediation_agent(context: str):
    """
    Takes raw CVE context and generates a technical action plan.
    """
    prompt = f"""You are an expert Remediation Agent. Based on this Threat Intel:
    
    {context}
    
    Write a 3-step technical action plan for a system administrator to fix this vulnerability. 
    Be specific (e.g., mention update commands, configuration changes, or workarounds)."""
    
    try:
        response = client.chat(
            model="qwen2.5:1.5b",
            messages=[{"role": "user", "content": prompt}]
        )
        return response['message']['content'].strip()
    except Exception as e:
        return f"Remediation Error: {e}"