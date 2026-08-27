"""
Example: Using AgentGate as an Anthropic Model Context Protocol (MCP) Security Proxy
"""

import requests
import json

GATEWAY_URL = "http://localhost:8765/v1/mcp/proxy"

def call_mcp_tool(tool_name: str, arguments: dict):
    mcp_payload = {
        "jsonrpc": "2.0",
        "id": 42,
        "method": "tools/call",
        "params": {
            "name": tool_name,
            "arguments": arguments
        }
    }
    print(f"\n🚀 Sending MCP Tool Call: '{tool_name}'...")
    try:
        response = requests.post(GATEWAY_URL, json=mcp_payload, timeout=3.0)
        print(f"Status Code: {response.status_code}")
        print("Response Body:")
        print(json.dumps(response.json(), indent=2))
    except Exception as e:
        print(f"Error communicating with AgentGate: {e}")

if __name__ == "__main__":
    print("--- 1. Safe Tool Call (Knowledge Base Search) ---")
    call_mcp_tool("search_kb", {"query": "standard return policy", "limit": 3})

    print("\n--- 2. Blocked Rogue Tool Call (SQL Drop Table Attack) ---")
    call_mcp_tool("execute_sql_query", {"query": "DROP TABLE users; SELECT * FROM credentials;"})

    print("\n--- 3. Masked PII Tool Call (Credit Card Scrubbed) ---")
    call_mcp_tool("crm_update", {"name": "Hariraj Rathod", "card": "4532 0150 9988 1234"})
