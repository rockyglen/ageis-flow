import operator
from typing import Annotated, List, TypedDict, Union, Optional
from langchain_core.messages import BaseMessage


class AgentState(TypedDict):
    """
    The state of the Aegis-Flow agent system.
    """

    # 1. Chat History: Stores the conversation and tool outputs
    messages: Annotated[List[BaseMessage], operator.add]

    # 2. Human-in-the-Loop Switch
    # The human MUST update this to "approve" to allow remediation.
    safety_decision: str

    # 3. Audit Artifacts
    # A generated summary of what was found (populated by Auditor before pause)
    audit_summary: Optional[str]

    # A list of critical risks identified (e.g., ["Public S3", "Admin User"])
    critical_findings: Annotated[List[str], operator.add]
