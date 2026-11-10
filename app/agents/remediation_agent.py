from ollama import Client
import os

client = Client(host=os.getenv("OLLAMA_URL", "http://host.docker.internal:11434"))

def remediation_agent(context: str):
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