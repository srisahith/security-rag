import re

def validate_output(answer: str, context: str) -> tuple[bool, str]:
    """
    Validates the LLM's output against the retrieved context.
    Returns (is_safe, reason).
    """
    if not answer or len(answer.strip()) == 0:
        return False, "Empty answer."
    
    # 🚨 1. REFUSAL CHECK (Good!)
    refusal_phrases = [
        "i don't know", "i do not know", "not enough information",
        "cannot be determined", "no relevant threat intel found"
    ]
    if any(phrase in answer.lower() for phrase in refusal_phrases):
        return True, "OK (Refusal)"
    
    # 🚨 2. EMPTY CONTEXT CHECK
    if ("No relevant threat intel found" in context or not context.strip()) and len(answer) > 200:
        return False, "LLM generated a long answer with no context (hallucination)."
    
    # 🚨 3. CVE HALLUCINATION CHECK
    answer_cves = set(re.findall(r'CVE-\d{4}-\d{4,7}', answer, re.IGNORECASE))
    if answer_cves:
        context_cves = set(re.findall(r'CVE-\d{4}-\d{4,7}', context, re.IGNORECASE))
        hallucinated = answer_cves - context_cves
        if hallucinated:
            return False, f"Hallucinated CVEs detected: {hallucinated}"
    
    # 🚨 4. STRICT NUMBER GROUNDING CHECK (Fixes 24988)
    # Any number with 4-8 digits in the answer must exist in the context
    answer_numbers = set(re.findall(r'\b\d{4,8}\b', answer))
    if answer_numbers:
        for num in answer_numbers:
            if num not in context:
                return False, f"Number '{num}' in answer not found in context (hallucination)."
    
    # 🚨 5. DATA LEAK CHECK
    sensitive_patterns = [
        r"postgresql://", r"DATABASE_URL", r"ghp_", r"sk-lf-", r"pk-lf-", r"password"
    ]
    for pattern in sensitive_patterns:
        if re.search(pattern, answer, re.IGNORECASE):
            return False, f"Sensitive data leak detected: {pattern}"
    
    # 🚨 6. COMMAND HALLUCINATION CHECK
    command_patterns = [r"sudo\s+", r"apt-get\s+", r"yum\s+", r"systemctl\s+", r"docker\s+"]
    for pattern in command_patterns:
        if re.search(pattern, answer) and not re.search(pattern, context):
            return False, f"Hallucinated command detected (not in context): {pattern}"
    
    return True, "OK"