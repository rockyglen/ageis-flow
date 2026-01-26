from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.messages import SystemMessage, HumanMessage, AIMessage
from langchain_core.tools import tool
from langgraph.prebuilt import ToolNode
import json
from dotenv import load_dotenv

from agents.state import AgentState

# --- IMPORT ALL TOOLS FROM YOUR MAIN.PY ---
# These imports are critical for the DIRECT EXECUTION strategy in the Remediator
from mcp_server.main import (
    get_agent_identity,
    list_iam_users,
    list_attached_user_policies,
    restrict_iam_user,
    list_s3_buckets,
    check_s3_security,
    remediate_s3,
    audit_vpc_network,
    remediate_vpc_flow_logs,
    audit_security_groups,
    revoke_security_group_ingress,
    audit_ec2_vulnerabilities,
    enforce_imdsv2,
    stop_instance,
    get_resource_owner,
)

load_dotenv()
# Initialize Gemini
llm = ChatGoogleGenerativeAI(model="gemini-3-pro-preview", temperature=0)

# --- DEFINE TOOL SETS ---

# 1. READ-ONLY AUDIT TOOLS
audit_tools_list = [
    get_agent_identity,
    list_iam_users,
    list_attached_user_policies,
    list_s3_buckets,
    check_s3_security,
    audit_vpc_network,
    audit_security_groups,
    audit_ec2_vulnerabilities,
    get_resource_owner,
]

# 2. DANGEROUS REMEDIATION TOOLS
remediation_tools_list = [
    restrict_iam_user,
    remediate_s3,
    remediate_vpc_flow_logs,
    revoke_security_group_ingress,
    enforce_imdsv2,
    stop_instance,
]

# Bind tools to the model
audit_llm = llm.bind_tools(audit_tools_list)
remediation_llm = llm.bind_tools(remediation_tools_list)

# --- NODES ---


def auditor_agent(state: AgentState):
    """
    Phase 1: Discovery & Forensics.
    """
    print("--- [NODE] AUDITOR AGENT ---")
    messages = state["messages"]

    # System Prompt: FORENSIC INVESTIGATOR (WITH TAG TRUTH)
    system_msg = SystemMessage(
        content=(
            "You are AEGIS-AUDITOR. Your mission is to perform a FORENSIC SECURITY SCAN.\n"
            "1. Identify Vulnerabilities (Public S3, Open SG, Unencrypted EC2).\n"
            "2. Identify High-Privilege Users (Admin).\n"
            "3. **CRITICAL STEP: ATTRIBUTION.**\n"
            "   - For EVERY vulnerability, you MUST call `get_resource_owner(resource_name)`.\n"
            "   - **ATTRIBUTION HIERARCHY (Use this strict order):**\n"
            "     - FIRST: Check the resource tags provided in the tool output. If a tag `CreatedBy` exists (e.g., 'dev-user-01'), that user is the **CONFIRMED CULPRIT**.\n"
            "     - SECOND: If no tag exists, rely on the CloudTrail owner found by `get_resource_owner`.\n"
            "   - Report the 'Owner' of every bad resource found based on this hierarchy.\n"
        )
    )

    # Ensure system message is first
    if not messages or not isinstance(messages[0], SystemMessage):
        messages = [system_msg] + messages

    response = audit_llm.invoke(messages)
    return {"messages": [response]}


def report_generator_node(state: AgentState):
    """
    Phase 2: Synthesis.
    Applies 'Insider Threat' policy and handles the 'SYSTEM SECURE' exit condition.
    """
    print("--- [NODE] REPORT GENERATOR ---")
    messages = state["messages"]

    # Updated Prompt: POLICY + EXIT CLAUSE
    summary_prompt = HumanMessage(
        content=(
            "Review the audit findings and create a REMEDIATION EXECUTION PLAN.\n\n"
            "**ZERO-RISK EXIT CLAUSE:**\n"
            "If NO critical vulnerabilities are found, you MUST respond with exactly:\n"
            "'✅ SYSTEM SECURE. No remediation actions required.'\n"
            "(This is critical to stop the automation process.)\n\n"
            "**SECURITY POLICY ENFORCEMENT (If Risks Found):**\n"
            "1. **Trusted Administrator:** Resources created by 'admin' (and lacking a suspect tag) are 'Legacy'. Remediate the resource, but DO NOT restrict the admin.\n"
            "2. **Insider Threat Protocol:** If a resource is tagged `CreatedBy: dev-user-01` OR CloudTrail shows `dev-user-01`, this is a **VIOLATION**.\n"
            "   - You MUST remediate the resource.\n"
            "   - You MUST ALSO call `restrict_iam_user` for 'dev-user-01' immediately.\n\n"
            "**EXECUTION PLAN FORMAT:**\n"
            "For each finding, output a line in this format:\n"
            "- 🔴 [CRITICAL] <Resource Name> is vulnerable -> ACTION: I will call <Tool Name>.\n"
            "- 🔴 [POLICY VIOLATION] User <Name> is non-compliant -> ACTION: I will call `restrict_iam_user`.\n\n"
            "Summarize the plan now."
        )
    )

    response = llm.invoke(messages + [summary_prompt])
    # Ensure we return a string, even if the model acts up
    if isinstance(response.content, list):
        clean_content = "".join([c["text"] for c in response.content if "text" in c])
    else:
        clean_content = str(response.content)
    # --------------------------------

    print(f"[DEBUG] Generated Report: {clean_content}")
    return {"audit_summary": clean_content, "messages": [response]}


def safety_gate_node(state: AgentState):
    """
    Phase 3: The Checkpoint.
    Checks if the system is secure. If so, skips the scary 'PAUSE' message.
    """
    summary = state.get("audit_summary", "No summary")
    
    # --- FIX START ---
    # Convert list-based content (Gemini quirk) to string for safety
    summary_str = str(summary)
    
    # Check for the magic "SYSTEM SECURE" string from the Report Generator
    if "SYSTEM SECURE" in summary_str:
        print("\n>>> AUDIT COMPLETE: ✅ SYSTEM SECURE. No risks detected.")
        print(">>> SKIPPING HUMAN REVIEW (Nothing to fix).\n")
        return # Do nothing, main.py will handle the exit
    # --- FIX END ---

    print(f"\n>>> AUDIT COMPLETE. FINDINGS: \n{summary_str}\n")
    print(">>> PAUSING FOR HUMAN REVIEW. (Remediation will strictly NOT proceed without approval).")
    pass


def remediator_agent(state: AgentState):
    """
    Phase 4: Enforcement.
    Executes fixes ONLY if safety_decision is 'approve'.
    """
    print("--- [NODE] REMEDIATOR AGENT ---")
    summary = state.get("audit_summary", "")
    decision = state.get("safety_decision", "deny")

    # 1. HARD SAFETY CHECK
    if decision.lower() != "approve":
        return {
            "messages": [
                AIMessage(
                    content=f"SAFETY BLOCK: User decision was '{decision}'. Remediation aborted."
                )
            ]
        }

    # 2. DISPATCH TABLE: Map string names to actual Python functions
    # This connects the text intent to the imported function objects
    FUNCTION_DISPATCH = {
        "restrict_iam_user": restrict_iam_user,
        "remediate_s3": remediate_s3,
        "remediate_vpc_flow_logs": remediate_vpc_flow_logs,
        "revoke_security_group_ingress": revoke_security_group_ingress,
        "stop_instance": stop_instance,
        "enforce_imdsv2": enforce_imdsv2,
    }

    # 3. INTENT MAPPING: Map AI's guessed names to valid keys in FUNCTION_DISPATCH
    INTENT_MAP = {
        # Network aliases
        "enable_vpc_flow_logs": "remediate_vpc_flow_logs",
        "remediate_vpc_flow_logs": "remediate_vpc_flow_logs",
        "revoke_security_group_ingress": "revoke_security_group_ingress",
        "remediate_security_group": "revoke_security_group_ingress",
        # Compute aliases
        "stop_ec2_instance": "stop_instance",
        "stop_instance": "stop_instance",
        "remediate_ec2_vulnerabilities": "stop_instance",
        # Storage aliases
        "set_s3_bucket_private": "remediate_s3",
        "remediate_s3_bucket": "remediate_s3",
        "remediate_s3_public_access": "remediate_s3",
        "remediate_s3": "remediate_s3",
        # IAM aliases
        "restrict_iam_user": "restrict_iam_user",
    }

    # 4. PARSE PLAN
    parser_prompt = SystemMessage(
        content=(
            "You are a Plan Parser. Convert the remediation plan into a JSON object.\n"
            'Output format: {"tools": [{"name": "...", "args": {...}}]}\n'
            "Use tool names from this list: " + ", ".join(INTENT_MAP.keys())
        )
    )

    # We use a HumanMessage to pass the plan content to avoid empty-content errors
    parser_input = HumanMessage(content=f"PLAN: {summary}")

    try:
        raw_response = llm.invoke([parser_prompt, parser_input])

        # Robust string extraction
        if isinstance(raw_response.content, list):
            raw_text = "".join([c["text"] for c in raw_response.content if "text" in c])
        else:
            raw_text = str(raw_response.content)

        clean_json = raw_text.replace("```json", "").replace("```", "").strip()
        plan_json = json.loads(clean_json)

        results = []

        # 5. EXECUTION LOOP
        tool_list = plan_json.get("tools", [])
        print(f"[DEBUG] Found {len(tool_list)} tasks. Starting direct execution...")

        for task in tool_list:
            ai_name = task["name"]
            args = task["args"]

            # Resolve to actual function
            real_func_name = INTENT_MAP.get(ai_name, ai_name)
            func_to_call = FUNCTION_DISPATCH.get(real_func_name)

            if "security_group_id" in args:
                args["group_id"] = args.pop("security_group_id")

            # --- ARGUMENT PATCHING FOR SECURITY GROUPS ---
            if real_func_name == "revoke_security_group_ingress":
                args.pop("cidr_ip", None)
                # Ensure required args exist, defaulting to standard SSH suppression
                if "protocol" not in args:
                    args["protocol"] = "tcp"
                if "from_port" not in args:
                    args["from_port"] = 22
                if "to_port" not in args:
                    args["to_port"] = 22
            # ---------------------------------------------

            if func_to_call:
                print(f"[EXEC] Calling {real_func_name} with {args}...")
                try:
                    # ACTUALLY CALL THE PYTHON FUNCTION
                    result_str = func_to_call(**args)
                    results.append(f"✅ {result_str}")
                except Exception as e:
                    results.append(f"❌ Error executing {real_func_name}: {str(e)}")
            else:
                results.append(f"⚠️ Unknown tool mapping: {ai_name}")

        # 6. REPORTING
        full_summary = "### 🛠️ REMEDIATION REPORT\n" + "\n".join(results)
        return {"messages": [AIMessage(content=full_summary)]}

    except Exception as e:
        print(f"[ERROR] Remediation failure: {e}")
        return {"messages": [AIMessage(content=f"Critical Agent Failure: {str(e)}")]}
