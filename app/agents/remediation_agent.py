from ollama import Client
import os

client = Client(host=os.getenv("OLLAMA_URL", "http://host.docker.internal:11434"))

def remediation_agent(context: str):
    # 🚨 GUARDRAIL: If context is empty, do NOT generate a fix
    if not context or "No relevant threat intel found" in context or context.strip() == "":
        return "I don't know. The retrieved context does not contain enough information to generate a remediation plan."
    
    prompt = f"""You are an expert Remediation Agent. Based on this Threat Intel:
    
    {context}
    
    STRICT RULES:
    1. You MUST use ONLY the information in the context above.
    2. Do NOT use outside knowledge. Do NOT invent commands, CVEs, or patches.
    3. If the context does not contain enough information to fix the vulnerability, reply EXACTLY: "I don't know based on the provided context."
    
    Write a 3-step technical action plan for a system administrator to fix this vulnerability."""
    
    try:
        response = client.chat(
            model="qwen2.5:1.5b",
            messages=[{"role": "user", "content": prompt}]
        )
        return response['message']['content'].strip()
    except Exception as e:
        return f"Remediation Error: {e}"