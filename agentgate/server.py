"""
AgentGate Server
FastAPI Web API Gateway and Management Console.
Provides MCP JSON-RPC proxy, REST evaluation endpoints, policy manager, and live web UI.
"""

import os
from typing import Dict, Any, Optional, List
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from .engine import PolicyEngine, PolicyRule, RuleAction
from .sanitizer import DataSanitizer
from .hitl import HITLManager

# Initialize core instances
sanitizer = DataSanitizer()
engine = PolicyEngine(sanitizer=sanitizer)
hitl = HITLManager()

app = FastAPI(
    title="AgentGate AI Firewall API",
    description="Zero-Trust Policy Engine & Real-Time Action Firewall for Autonomous AI Agents",
    version="1.0.0"
)

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Request Models
class EvaluationRequest(BaseModel):
    tool_name: str
    tool_args: Dict[str, Any]
    session_id: Optional[str] = "default_session"
    recursion_depth: Optional[int] = 1

class MCPJsonRpcRequest(BaseModel):
    jsonrpc: str = "2.0"
    id: Optional[Any] = 1
    method: str
    params: Optional[Dict[str, Any]] = None

class ToggleRuleRequest(BaseModel):
    rule_id: str
    enabled: bool

# Web Dashboard UI Route
@app.get("/", response_class=HTMLResponse)
async def serve_dashboard():
    static_file = os.path.join(os.path.dirname(__file__), "static", "index.html")
    if os.path.exists(static_file):
        with open(static_file, "r") as f:
            return HTMLResponse(content=f.read())
    return HTMLResponse("<h1>AgentGate AI API Active</h1>")

# Core REST Tool Evaluation Route
@app.post("/v1/evaluate")
async def evaluate_action(req: EvaluationRequest):
    decision = engine.evaluate(
        tool_name=req.tool_name,
        tool_args=req.tool_args,
        session_id=req.session_id or "default_session",
        recursion_depth=req.recursion_depth or 1
    )

    if decision.action == RuleAction.REQUIRE_HITL:
        hitl.request_approval(
            decision_id=decision.decision_id,
            tool_name=decision.tool_name,
            tool_args=decision.sanitized_args,
            reason=decision.reason,
            risk_score=decision.risk_score
        )

    return decision

# Anthropic Model Context Protocol (MCP) JSON-RPC Proxy
@app.post("/v1/mcp/proxy")
async def mcp_proxy(req: MCPJsonRpcRequest):
    """
    Direct Model Context Protocol (MCP) proxy endpoint.
    Intercepts `tools/call` JSON-RPC method, inspects parameters, and validates against policies.
    """
    if req.method == "tools/call":
        tool_name = req.params.get("name", "unknown_tool")
        arguments = req.params.get("arguments", {})

        decision = engine.evaluate(tool_name=tool_name, tool_args=arguments)

        if decision.action == RuleAction.BLOCK:
            return JSONResponse(status_code=403, content={
                "jsonrpc": "2.0",
                "id": req.id,
                "error": {
                    "code": -32000,
                    "message": f"AgentGate Security Block: {decision.reason}",
                    "data": decision.model_dump()
                }
            })

        if decision.action == RuleAction.REQUIRE_HITL:
            hitl.request_approval(
                decision_id=decision.decision_id,
                tool_name=tool_name,
                tool_args=decision.sanitized_args,
                reason=decision.reason,
                risk_score=decision.risk_score
            )
            return JSONResponse(status_code=202, content={
                "jsonrpc": "2.0",
                "id": req.id,
                "error": {
                    "code": -32001,
                    "message": f"AgentGate Action Paused: Human-in-the-Loop verification required. {decision.reason}",
                    "data": decision.model_dump()
                }
            })

        # Sanitized / Allowed
        return {
            "jsonrpc": "2.0",
            "id": req.id,
            "result": {
                "status": "APPROVED",
                "sanitized_arguments": decision.sanitized_args,
                "cryptographic_receipt": decision.cryptographic_receipt,
                "latency_ms": decision.evaluation_time_ms
            }
        }

    # Pass-through for tools/list or initialize
    return {
        "jsonrpc": "2.0",
        "id": req.id,
        "result": {"status": "PASSTHROUGH", "method": req.method}
    }

# Policy Management Routes
@app.get("/v1/rules")
async def get_rules():
    return engine.rules

@app.post("/v1/rules/toggle")
async def toggle_rule(req: ToggleRuleRequest):
    success = engine.toggle_rule(req.rule_id, req.enabled)
    if not success:
        raise HTTPException(status_code=404, detail="Rule ID not found")
    return {"status": "success", "rule_id": req.rule_id, "enabled": req.enabled}

# Audit Log Route
@app.get("/v1/audit")
async def get_audit_logs():
    return {"audit_log": engine.audit_log[-50:]}

# Health Check Route
@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "version": "1.0.0",
        "active_rules_count": len([r for r in engine.rules.values() if r.enabled]),
        "total_evaluated_actions": len(engine.audit_log)
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8765)
