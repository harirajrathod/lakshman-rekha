"""
Example: Wrapping LangChain / Custom Agent Tool Execution with AgentGate Python SDK
"""

from agentgate.client import AgentGateClient, AgentGateSecurityException

def execute_agent_action():
    gate = AgentGateClient(gateway_url="http://localhost:8765")
    
    # 1. Safe tool call
    try:
        clean_args = gate.guard_tool("update_profile", {"user_id": 101, "bio": "Software engineer"})
        print(f"✓ Action Allowed! Executing with sanitized args: {clean_args}")
    except AgentGateSecurityException as e:
        print(f"✗ Action Blocked: {e}")

    # 2. Dangerous SQL call
    try:
        clean_args = gate.guard_tool("execute_db", {"sql": "TRUNCATE TABLE audit_records;"})
        print(f"✓ Action Allowed: {clean_args}")
    except AgentGateSecurityException as e:
        print(f"🛡️ AgentGate Intercepted & Blocked: {e}")

if __name__ == "__main__":
    execute_agent_action()
