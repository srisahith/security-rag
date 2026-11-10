import re

# 🚨 1. PROMPT INJECTION PATTERNS
# These attempt to override the system prompt or extract the context
INJECTION_PATTERNS = [
    r"ignore\s+(all\s+)?previous\s+instructions",
    r"ignore\s+(all\s+)?above\s+instructions",
    r"disregard\s+(all\s+)?prior",
    r"you\s+are\s+now\s+(a|an)\s+",
    r"system\s+prompt",
    r"reveal\s+your\s+instructions",
    r"print\s+your\s+prompt",
    r"</?system>", # XML tag injection
    r"<\|im_start\|>", # Chat template injection
]

# 🚨 2. JAILBREAK PATTERNS (DAN, Developer Mode, etc.)
JAILBREAK_PATTERNS = [
    r"do\s+anything\s+now",
    r"DAN\s+mode",
    r"developer\s+mode",
    r"act\s+as\s+if\s+you\s+have\s+no\s+restrictions",
    r"bypass\s+your\s+safety",
]

# 🚨 3. MALICIOUS SQL PATTERNS (Defense in Depth)
# If the LLM generates this, the MCP Server should reject it
MALICIOUS_SQL_PATTERNS = [
    r"drop\s+table",
    r"delete\s+from",
    r"truncate\s+table",
    r"alter\s+table",
    r"insert\s+into",
    r"update\s+.*\s+set",
    r"union\s+select",
    r"information_schema",
    r"pg_catalog",
]

def validate_input(question: str) -> tuple[bool, str]:
    """
    Validates the user input against injection, jailbreak, and SQL attacks.
    Returns (is_safe, reason).
    """
    if not question or len(question.strip()) == 0:
        return False, "Empty question."
    
    if len(question) > 2000:
        return False, "Question exceeds maximum length (2000 chars)."
    
    question_lower = question.lower()
    
    # Check Prompt Injection
    for pattern in INJECTION_PATTERNS:
        if re.search(pattern, question_lower):
            return False, f"Prompt injection detected: {pattern}"
    
    # Check Jailbreak
    for pattern in JAILBREAK_PATTERNS:
        if re.search(pattern, question_lower):
            return False, f"Jailbreak attempt detected: {pattern}"
    
    # Check Malicious SQL
    for pattern in MALICIOUS_SQL_PATTERNS:
        if re.search(pattern, question_lower):
            return False, f"Malicious SQL detected: {pattern}"
    
    return True, "OK"

def validate_tool_input(question: str) -> tuple[bool, str]:
    """
    Stricter validation for the MCP Server.
    Rejects anything that looks like an attack.
    """
    if not question or len(question.strip()) == 0:
        return False, "Empty tool input."
    
    if len(question) > 1000:
        return False, "Tool input exceeds 1000 chars."
    
    # Reject any SQL keywords
    for pattern in MALICIOUS_SQL_PATTERNS:
        if re.search(pattern, question.lower()):
            return False, f"SQL keyword blocked in tool input: {pattern}"
    
    return True, "OK"