import sys
from langchain_core.messages import HumanMessage, AIMessage
from agents.graph import app


def run_interactive_session():
    """
    Main execution loop for AEGIS-FLOW.
    Handles the Audit -> Pause -> Remediation workflow.
    """
    print("🚀 AEGIS-FLOW: SECURE AGENTIC ORCHESTRATION INITIALIZED")
    print("=======================================================")

    # 1. Configuration (Thread ID is required for memory/checkpoints)
    config = {"configurable": {"thread_id": "1"}}

    # 2. Initial Input
    print("\n[SYSTEM] Initializing Audit Scan...")
    initial_input = {
        "messages": [HumanMessage(content="Start the security audit.")],
        "safety_decision": "pending",
    }

    # 3. RUN: Phase 1 (Audit)
    try:
        for event in app.stream(initial_input, config, stream_mode="values"):
            message = event["messages"][-1]
            if hasattr(message, "content") and message.content:
                tool_calls = getattr(message, "tool_calls", [])
                if not tool_calls:
                    if isinstance(message, AIMessage):
                        sender = (
                            "AUDITOR" if "Auditor" in str(message.content) else "AGENT"
                        )
                        # CLEAN LOGS HERE:
                        content = message.content
                        text_to_print = (
                            content[0]["text"] if isinstance(content, list) else content
                        )

                    else:
                        sender = "USER"
                        text_to_print = message.content
                    print(f"\n[{sender}]: {text_to_print}")
    except Exception as e:
        import traceback

        traceback.print_exc()
        print(f"Error during audit: {e}")
        return

    # 4. PAUSE: Check State at Interrupt
    snapshot = app.get_state(config)

    if not snapshot.next:
        print(
            "\n[SYSTEM] Process finished without interruption (No risks found or Error)."
        )
        return

    # Extract the Audit Summary
    audit_summary = snapshot.values.get("audit_summary", "No summary provided.")

    # =========================================================================
    # THE FIX: Cast to string to handle Gemini's List/Dict content structure
    # =========================================================================
    audit_summary_str = str(audit_summary)

    if "SYSTEM SECURE" in audit_summary_str:
        print("\n" + "=" * 60)
        print("✅ AUDIT CONCLUSION: SYSTEM SECURE")
        print("=" * 60)
        print("\n[SYSTEM] No remediation actions required. Exiting process.")
        print("=======================================================")
        return  # <--- AUTO-EXIT HERE

    # 5. IF NOT SECURE -> SAFETY GATE
    print("\n" + "=" * 60)
    print("🛑 SAFETY GATE: HUMAN INTERVENTION REQUIRED")
    print("=" * 60)
    # We print the string version so it looks cleaner in logs if it's a list
    print(f"\n📝 AUDIT FINDINGS:\n{audit_summary}")
    print("-" * 60)

    # 6. INPUT: Human Decision
    user_decision = (
        input(
            "\n>>> Do you authorize remediation? (Type 'approve' to proceed, anything else to abort): "
        )
        .strip()
        .lower()
    )

    if user_decision != "approve":
        print("\n❌ Permission Denied. Aborting execution.")
        return

    # 7. RESUME: Phase 2 (Remediation)
    print("\n✅ Permission Granted. Resuming Workflow...")
    app.update_state(config, {"safety_decision": "approve"})

    for event in app.stream(None, config, stream_mode="values"):
        message = event["messages"][-1]
        if hasattr(message, "content") and message.content:
            tool_calls = getattr(message, "tool_calls", [])
            if tool_calls:
                for tc in tool_calls:
                    print(f"\n[REMEDIATOR]: 🛠️  EXECUTING TOOL: {tc['name']}...")

            # If it's just text, print the text
            else:
                content = message.content
                text_to_print = (
                    content[0]["text"] if isinstance(content, list) else content
                )
                print(f"\n[REMEDIATOR]: {text_to_print}")

    print("\n=======================================================")
    print("🏁 AEGIS-FLOW WORKFLOW COMPLETE")
    print("=======================================================")


if __name__ == "__main__":
    run_interactive_session()
