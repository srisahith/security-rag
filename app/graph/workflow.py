from typing import TypedDict, List
from langgraph.graph import StateGraph, END
import asyncio
import json

from app.agents.triage_agent import triage_agent
from app.agents.remediation_agent import remediation_agent
from app.mcp.mcp_client import call_mcp_search

# 🚨 1. Define the State (Memory passed between nodes)
class AgentState(TypedDict):
    question: str
    needs_search: bool
    needs_remediation: bool
    context: str
    remediation_plan: str
    final_answer: str

# 🚨 2. Define the Nodes (The steps)
def triage_node(state: AgentState):
    decision = triage_agent(state["question"])
    print(f"[GRAPH] LLM Triage Decision: {decision}")
    
    # 🚨 DETERMINISTIC GUARDRAIL
    # If the question contains remediation keywords, force it to True
    remediation_keywords = ["fix", "patch", "remediate", "mitigate", "solution", "how to fix", "how do i fix", "resolve"]
    question_lower = state["question"].lower()
    
    needs_remediation = decision.get("needs_remediation", False)
    if any(keyword in question_lower for keyword in remediation_keywords):
        print(f"[GRAPH] Guardrail: Forcing needs_remediation=True")
        needs_remediation = True
    
    # If an ID is detected, force search
    needs_search = decision.get("needs_search", True)
    if "cve-" in question_lower or "vdb-" in question_lower or "ghsa-" in question_lower:
        print(f"[GRAPH] Guardrail: Forcing needs_search=True")
        needs_search = True
    
    return {
        "needs_search": needs_search,
        "needs_remediation": needs_remediation
    }

def search_node(state: AgentState):
    print(f"[GRAPH] Calling MCP Tool for: {state['question']}")
    # Run async MCP call inside the sync graph
    context = asyncio.run(call_mcp_search(state["question"]))
    return {"context": context}

def remediation_node(state: AgentState):
    print(f"[GRAPH] Generating Remediation Plan...")
    plan = remediation_agent(state["context"])
    return {"remediation_plan": plan}

def finalize_node(state: AgentState):
    answer = f"### Threat Intel Analysis\n{state.get('context', 'No search performed.')}\n\n### Remediation Plan\n{state.get('remediation_plan', 'No remediation requested.')}"
    return {"final_answer": answer}

# 🚨 3. Define the Routing Logic (Edges)
def route_after_triage(state: AgentState):
    if state["needs_search"]:
        return "search"
    elif state["needs_remediation"]:
        return "remediation"
    else:
        return "finalize"

def route_after_search(state: AgentState):
    if state["needs_remediation"]:
        return "remediation"
    return "finalize"

# 🚨 4. Build the Graph
workflow = StateGraph(AgentState)

workflow.add_node("triage", triage_node)
workflow.add_node("search", search_node)
workflow.add_node("remediation", remediation_node)
workflow.add_node("finalize", finalize_node)

workflow.set_entry_point("triage")

workflow.add_conditional_edges("triage", route_after_triage)
workflow.add_conditional_edges("search", route_after_search)
workflow.add_edge("remediation", "finalize")
workflow.add_edge("finalize", END)

# Compile the graph
agent_graph = workflow.compile()