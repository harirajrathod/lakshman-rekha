"""
End-to-End MCP Proxy Overhead Benchmark
Measures:
1. Baseline: Direct Client -> Downstream Tool Server
2. AgentGate: Client -> AgentGate Security Proxy -> Downstream Tool Server
Calculates: Real Net Gateway Overhead (Delta) and p99 overhead.
"""

import time
import statistics
import threading
import json
import uvicorn
from fastapi import FastAPI
import requests
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from agentgate.server import app as agentgate_app

# 1. Downstream Tool Server (Mock MCP Server)
downstream_app = FastAPI()

@downstream_app.post("/execute")
async def mock_tool_execution(payload: dict):
    # Simulates light DB query / microservice logic (~1.5ms)
    time.sleep(0.0015)
    return {"status": "success", "result": f"Executed {payload.get('tool_name')}"}

def run_servers():
    config1 = uvicorn.Config(downstream_app, host="127.0.0.1", port=8766, log_level="error")
    config2 = uvicorn.Config(agentgate_app, host="127.0.0.1", port=8765, log_level="error")
    
    t1 = threading.Thread(target=uvicorn.Server(config1).run, daemon=True)
    t2 = threading.Thread(target=uvicorn.Server(config2).run, daemon=True)
    t1.start()
    t2.start()
    time.sleep(1.5)

def run_e2e_benchmark(num_trials: int = 500):
    run_servers()
    
    session = requests.Session()
    
    # Payload
    payload = {
        "tool_name": "search_knowledge_base",
        "tool_args": {"query": "customer return policy", "top_k": 3}
    }
    
    mcp_proxy_payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "search_knowledge_base",
            "arguments": {"query": "customer return policy", "top_k": 3}
        }
    }

    print(f"🚀 Running End-to-End MCP Proxy Benchmark ({num_trials} trials each)...")
    
    # 1. Measure Baseline: Client -> Direct Downstream Tool Server
    baseline_lats = []
    for _ in range(num_trials):
        t0 = time.perf_counter()
        resp = session.post("http://127.0.0.1:8766/execute", json=payload)
        baseline_lats.append((time.perf_counter() - t0) * 1000.0)

    # 2. Measure AgentGate Proxy Path: Client -> AgentGate Proxy (Inspection + Sanitization + Receipt)
    agentgate_lats = []
    for _ in range(num_trials):
        t0 = time.perf_counter()
        resp = session.post("http://127.0.0.1:8765/v1/mcp/proxy", json=mcp_proxy_payload)
        agentgate_lats.append((time.perf_counter() - t0) * 1000.0)

    # Calculate Overhead Delta
    b_mean = statistics.mean(baseline_lats)
    b_p50 = statistics.median(baseline_lats)
    b_p99 = sorted(baseline_lats)[int(num_trials * 0.99)]

    ag_mean = statistics.mean(agentgate_lats)
    ag_p50 = statistics.median(agentgate_lats)
    ag_p99 = sorted(agentgate_lats)[int(num_trials * 0.99)]

    overhead_mean = ag_mean - b_mean
    overhead_p50 = ag_p50 - b_p50
    overhead_p99 = ag_p99 - b_p99

    print("\n" + "="*65)
    print("📊 END-TO-END MCP GATEWAY OVERHEAD REPORT")
    print("="*65)
    print(f"1. Direct Downstream Baseline:  Mean: {b_mean:.3f} ms | p50: {b_p50:.3f} ms | p99: {b_p99:.3f} ms")
    print(f"2. AgentGate Proxy Path:        Mean: {ag_mean:.3f} ms | p50: {ag_p50:.3f} ms | p99: {ag_p99:.3f} ms")
    print("-" * 65)
    print(f"⚡ NET PROXY OVERHEAD (Delta):  Mean: {overhead_mean:.3f} ms | p50: {overhead_p50:.3f} ms | p99: {overhead_p99:.3f} ms")
    print("="*65)

if __name__ == '__main__':
    run_e2e_benchmark(500)
