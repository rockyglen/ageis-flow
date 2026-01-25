from langgraph.graph import StateGraph, END
from langgraph.prebuilt import ToolNode
from langgraph.checkpoint.memory import MemorySaver

from agents.state import AgentState
from agents.nodes import (
    auditor_agent,
    report_generator_node,
    remediator_agent,
    safety_gate_node,
    audit_tools_list,
    remediation_tools_list,
)

# Initialize Tool Executors
audit_tool_node = ToolNode(audit_tools_list)
remediation_tool_node = ToolNode(remediation_tools_list)

# --- CONDITIONAL EDGES ---


def should_audit_continue(state: AgentState):
    """
    Loop until the Auditor stops calling tools and produces a text response.
    """
    last_message = state["messages"][-1]
    if last_message.tool_calls:
        return "audit_tools"
    return "report_generator"  # Go to summary instead of straight to gate


def should_remediate_continue(state: AgentState):
    last_message = state["messages"][-1]
    if last_message.tool_calls:
        return "remediation_tools"
    return "end"


# --- BUILD GRAPH ---

workflow = StateGraph(AgentState)

# 1. Add Nodes
workflow.add_node("auditor", auditor_agent)
workflow.add_node("audit_tools", audit_tool_node)
workflow.add_node("report_generator", report_generator_node)  # NEW NODE
workflow.add_node("safety_gate", safety_gate_node)
workflow.add_node("remediator", remediator_agent)
workflow.add_node("remediation_tools", remediation_tool_node)

# 2. Set Entry Point
workflow.set_entry_point("auditor")

# 3. Connect Edges
# Audit Loop
workflow.add_conditional_edges(
    "auditor",
    should_audit_continue,
    {"audit_tools": "audit_tools", "report_generator": "report_generator"},
)
workflow.add_edge("audit_tools", "auditor")

# Report -> Safety Gate
workflow.add_edge("report_generator", "safety_gate")

# Safety Gate -> Remediator (The 'interrupt' happens here)
workflow.add_edge("safety_gate", "remediator")

# Remediation Loop
workflow.add_conditional_edges(
    "remediator",
    should_remediate_continue,
    {"remediation_tools": "remediation_tools", "end": END},
)
workflow.add_edge("remediation_tools", "remediator")

# 4. Compile
memory = MemorySaver()

app = workflow.compile(checkpointer=memory, interrupt_before=["remediator"])
