import re

def validate_output(answer: str, context: str) -> tuple[bool, str]:
    if not answer or len(answer.strip()) == 0:
        return False, "Empty answer."
    
    # 🚨 1. REFUSAL CHECK (Good!)
    refusal_phrases = ["i don't know", "i do not know", "not enough information", "no relevant threat intel found"]
    if any(phrase in answer.lower() for phrase in refusal_phrases):
        return True, "OK (Refusal)"
    
    # 🚨 2. EMPTY CONTEXT CHECK
    if ("No relevant threat intel found" in context or not context.strip()) and len(answer) > 200:
        return False, "LLM generated a long answer with no context (hallucination)."
    
    # 🚨 3. CVE HALLUCINATION CHECK (Only for CVE IDs, not general numbers)
    answer_cves = set(re.findall(r'CVE-\d{4}-\d{4,7}', answer, re.IGNORECASE))
    if answer_cves:
        context_cves = set(re.findall(r'CVE-\d{4}-\d{4,7}', context, re.IGNORECASE))
        hallucinated = answer_cves - context_cves
        if hallucinated:
            return False, f"Hallucinated CVEs detected: {hallucinated}"
    
    # 🚨 4. DATA LEAK CHECK
    sensitive_patterns = [r"postgresql://", r"DATABASE_URL", r"ghp_", r"sk-lf-", r"pk-lf-", r"password"]
    for pattern in sensitive_patterns:
        if re.search(pattern, answer, re.IGNORECASE):
            return False, f"Sensitive data leak detected: {pattern}"
    
    # 🚨 5. COMMAND HALLUCINATION CHECK
    command_patterns = [r"sudo\s+", r"apt-get\s+", r"yum\s+", r"systemctl\s+", r"docker\s+"]
    for pattern in command_patterns:
        if re.search(pattern, answer) and not re.search(pattern, context):
            return False, f"Hallucinated command detected (not in context): {pattern}"
    
    return True, "OK"