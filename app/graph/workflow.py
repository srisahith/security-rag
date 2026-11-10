from typing import TypedDict
from langgraph.graph import StateGraph, END
import asyncio

from app.agents.triage_agent import triage_agent
from app.agents.remediation_agent import remediation_agent
from app.mcp.mcp_client import call_mcp_search
from app.guardrails.input_guard import validate_input
from app.guardrails.output_guard import validate_output

# 🚨 1. STATE DEFINITION
class AgentState(TypedDict):
    question: str
    needs_search: bool
    needs_remediation: bool
    context: str
    remediation_plan: str
    final_answer: str
    error: str
    blocked: bool  # 🚨 ADD THIS

# 🚨 2. NODE FUNCTIONS

def input_guardrail_node(state: AgentState):
    is_safe, reason = validate_input(state["question"])
    if not is_safe:
        print(f"[GUARDRAIL] Input BLOCKED: {reason}")
        return {"error": reason, "final_answer": f"❌ Blocked by Input Guardrail: {reason}"}
    return {"error": ""}

def triage_node(state: AgentState):
    decision = triage_agent(state["question"])
    print(f"[GRAPH] LLM Triage Decision: {decision}")
    
    question_lower = state["question"].lower()
    
    # 🚨 DEFAULT: Remediation is always TRUE
    needs_remediation = True
    
    # 🚨 EXCEPTION: Only turn it off if user explicitly opts out
    opt_out_keywords = [
        "no fix", "no remediation", "don't fix", "do not fix", 
        "just tell me", "only tell me", "no need to fix", "skip remediation"
    ]
    if any(keyword in question_lower for keyword in opt_out_keywords):
        print(f"[GRAPH] Guardrail: User opted out of remediation.")
        needs_remediation = False
    
    # 🚨 SEARCH: Default True
    needs_search = True
    if "hello" in question_lower or "hi" == question_lower.strip():
        needs_search = False
    
    # 🚨 FORCE SEARCH if ID detected
    if "cve-" in question_lower or "vdb-" in question_lower or "ghsa-" in question_lower:
        print(f"[GRAPH] Guardrail: Forcing needs_search=True for ID.")
        needs_search = True
    
    return {"needs_search": needs_search, "needs_remediation": needs_remediation}

def search_node(state: AgentState):
    print(f"[GRAPH] Calling MCP Tool for: {state['question']}")
    context = asyncio.run(call_mcp_search(state["question"]))
    if not context:
        context = "No relevant threat intel found."
    return {"context": context}

def remediation_node(state: AgentState):
    print(f"[GRAPH] Generating Remediation Plan...")
    plan = remediation_agent(state["context"])
    return {"remediation_plan": plan}

def output_guardrail_node(state: AgentState):
    is_safe, reason = validate_output(state.get("final_answer", ""), state.get("context", ""))
    if not is_safe:
        print(f"[GUARDRAIL] Output BLOCKED: {reason}")
        return {"blocked": True, "final_answer": f"⚠️ Response blocked by Output Guardrail: {reason}"}
    return {"blocked": False}


def finalize_node(state: AgentState):
    if state.get("error"):
        return {"final_answer": state["final_answer"]}
    
    context = state.get('context', 'N/A')
    remediation = state.get('remediation_plan', 'N/A')
    
    # 🚨 If the output guardrail blocked the answer, refuse cleanly
    if state.get("blocked"):
        answer = "⚠️ I don't know based on the current threat intel. The requested information is not in the database."
    # 🚨 If the LLM refused, show a clean refusal
    elif "i don't know" in remediation.lower() or "not enough information" in remediation.lower():
        answer = f"### Threat Intel\n{context}\n\n### Remediation\n⚠️ The AI could not generate a remediation plan because the context did not contain enough information."
    else:
        answer = f"### Threat Intel\n{context}\n\n### Remediation\n{remediation}"
    
    return {"final_answer": answer}

# 🚨 3. ROUTING FUNCTIONS

def route_after_input_guard(state: AgentState):
    if state.get("error"):
        return "finalize"
    return "triage"

def route_after_triage(state: AgentState):
    if state["needs_search"]:
        return "search"
    elif state["needs_remediation"]:
        return "remediation"
    return "finalize"

def route_after_search(state: AgentState):
    if state["needs_remediation"]:
        return "remediation"
    return "output_guard"

# 🚨 4. GRAPH CONSTRUCTION (Must be after all functions are defined)
workflow = StateGraph(AgentState)

workflow.add_node("input_guard", input_guardrail_node)
workflow.add_node("triage", triage_node)
workflow.add_node("search", search_node)
workflow.add_node("remediation", remediation_node)
workflow.add_node("finalize", finalize_node)
workflow.add_node("output_guard", output_guardrail_node)

workflow.set_entry_point("input_guard")
workflow.add_conditional_edges("input_guard", route_after_input_guard)
workflow.add_conditional_edges("triage", route_after_triage)
workflow.add_conditional_edges("search", route_after_search)
workflow.add_edge("remediation", "output_guard")
workflow.add_edge("output_guard", "finalize")
workflow.add_edge("finalize", END)

agent_graph = workflow.compile()