"""
AgentGateClient Python SDK
Provides a lightweight client to intercept and validate tool calls before execution.
"""

import requests
from typing import Dict, Any, Optional

class AgentGateSecurityException(Exception):
    def __init__(self, message: str, decision: Dict[str, Any]):
        super().__init__(message)
        self.decision = decision

class AgentGateClient:
    def __init__(self, gateway_url: str = "http://localhost:8765", api_key: Optional[str] = None):
        self.gateway_url = gateway_url.rstrip("/")
        self.api_key = api_key
        self.headers = {"Content-Type": "application/json"}
        if api_key:
            self.headers["Authorization"] = f"Bearer {api_key}"

    def evaluate_tool(self, tool_name: str, tool_args: Dict[str, Any], session_id: str = "default_session", recursion_depth: int = 1) -> Dict[str, Any]:
        """
        Sends tool parameters to AgentGate firewall for pre-execution evaluation.
        """
        payload = {
            "tool_name": tool_name,
            "tool_args": tool_args,
            "session_id": session_id,
            "recursion_depth": recursion_depth
        }
        resp = requests.post(f"{self.gateway_url}/v1/evaluate", json=payload, headers=self.headers, timeout=5.0)
        resp.raise_for_status()
        return resp.json()

    def guard_tool(self, tool_name: str, tool_args: Dict[str, Any], session_id: str = "default_session") -> Dict[str, Any]:
        """
        Guards tool execution: raises AgentGateSecurityException if blocked, returns sanitized args if allowed/masked.
        """
        result = self.evaluate_tool(tool_name, tool_args, session_id)
        action = result.get("action")

        if action == "BLOCK":
            raise AgentGateSecurityException(f"AgentGate Blocked Execution: {result.get('reason')}", result)
        
        if action == "REQUIRE_HITL":
            raise AgentGateSecurityException(f"AgentGate Paused Execution (HITL Required): {result.get('reason')}", result)

        return result.get("sanitized_args", tool_args)
