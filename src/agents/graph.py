import json
from typing import TypedDict, Annotated, List
import operator
from langchain_core.messages import SystemMessage, HumanMessage
from langchain_google_genai import ChatGoogleGenerativeAI
from langgraph.graph import StateGraph, END
from src.agents.tools import query_network_history, query_endpoint_history, search_threat_intelligence

# 1. Define Agent State Schema
class SOCAgentState(TypedDict):
    alert: dict
    triage_notes: str
    threat_intel: str
    remediation_plan: str
    messages: Annotated[List, operator.add]

# Initialize Gemini LLM
llm = ChatGoogleGenerativeAI(model="gemini-2.5-flash", temperature=0.1)

# 2. Node 1: Triage Agent
def triage_node(state: SOCAgentState):
    alert = state["alert"]
    details = alert.get("details", {})
    
    # Gather evidence using DuckDB tools
    evidence = ""
    if "src_ip" in details:
        ip = details["src_ip"]
        evidence = query_network_history.invoke({"ip_address": ip})
    elif "host" in details:
        host = details["host"]
        evidence = query_endpoint_history.invoke({"host_or_user": host})

    sys_msg = SystemMessage(content="You are an expert Security Operations Center (SOC) Triage Specialist.")
    human_msg = HumanMessage(content=f"""Analyze this alert and gathered log evidence:
ALERT: {json.dumps(alert)}
TELEMETRY EVIDENCE: {evidence}

Provide a concise forensic summary answering:
1. Is this likely a true positive or false positive?
2. What specific evidence supports your conclusion?
3. What entity (IP, Host, User) is compromised?""")

    response = llm.invoke([sys_msg, human_msg])
    return {
        "triage_notes": response.content,
        "messages": [HumanMessage(content=f"Triage Completed: {response.content}")]
    }

# 3. Node 2: Threat Intelligence Agent
def threat_intel_node(state: SOCAgentState):
    triage_notes = state["triage_notes"]
    intel_results = search_threat_intelligence.invoke({"query_text": triage_notes[:200]})

    sys_msg = SystemMessage(content="You are a Threat Intelligence Analyst.")
    human_msg = HumanMessage(content=f"""Review these triage notes and vector search threat database results:
TRIAGE NOTES: {triage_notes}
INTEL MATCHES: {intel_results}

Map this activity to MITRE ATT&CK techniques or known CVEs and summarize the threat actor capability and objectives.""")

    response = llm.invoke([sys_msg, human_msg])
    return {
        "threat_intel": response.content,
        "messages": [HumanMessage(content=f"Threat Intel Mapped: {response.content}")]
    }

# 4. Node 3: Remediation & Containment Agent
def remediation_node(state: SOCAgentState):
    triage_notes = state["triage_notes"]
    threat_intel = state["threat_intel"]

    sys_msg = SystemMessage(content="You are an Incident Response Remediation Specialist.")
    human_msg = HumanMessage(content=f"""Based on the Triage and Threat Intel, generate an actionable Incident Response Plan.
TRIAGE: {triage_notes}
INTEL: {threat_intel}

Provide:
1. Containment Action (e.g., Firewall command, user disablement).
2. Recommended Detection Rule (e.g., Sigma rule or YARA logic).
3. Severity Level (LOW, MEDIUM, HIGH, CRITICAL).""")

    response = llm.invoke([sys_msg, human_msg])
    return {
        "remediation_plan": response.content,
        "messages": [HumanMessage(content=f"Remediation Plan Generated: {response.content}")]
    }

# 5. Build LangGraph Workflow
workflow = StateGraph(SOCAgentState)

workflow.add_node("triage", triage_node)
workflow.add_node("threat_intel", threat_intel_node)
workflow.add_node("remediation", remediation_node)

workflow.set_entry_point("triage")
workflow.add_edge("triage", "threat_intel")
workflow.add_edge("threat_intel", "remediation")
workflow.add_edge("remediation", END)

soc_agent_graph = workflow.compile()