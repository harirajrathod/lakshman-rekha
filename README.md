<div align="center">

# 🛡️ AgentGate AI
### The Zero-Trust Policy Engine & Real-Time Action Firewall for Autonomous AI Agents

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python Version](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-blue)](https://www.python.org/)
[![Latency SLA](https://img.shields.io/badge/Latency-%3C%200.05ms-emerald.svg)](#benchmarks)
[![Throughput](https://img.shields.io/badge/Throughput-21%2C000%2B%20req%2Fsec-indigo.svg)](#benchmarks)
[![EU AI Act Ready](https://img.shields.io/badge/Compliance-EU%20AI%20Act%20%7C%20SOC2-orange.svg)](#compliance)

**Prevent autonomous AI agents from hallucinating rogue API calls, wiping production databases, leaking PII, or executing unauthorized financial transactions.**

[Quickstart](#quickstart-in-30-seconds) • [Architecture](#architecture) • [Features](#key-features) • [Dashboard](#live-web-management-console) • [Benchmarks](#benchmarks) • [MCP Proxy](#anthropic-mcp-integration)

</div>

---

## ⚡ Why AgentGate? (The Agent Blast Radius)

Between 2023 and 2025, enterprise AI was purely informational (RAG, chatbots). Today, enterprise agents operate **autonomously** with direct write privileges to production databases, payment gateways, and cloud IAM infrastructure.

Existing observability tools (Datadog, LangSmith, Arize) are **post-mortem loggers**—they alert you *after* the rogue payment has processed or the database table has been dropped. Traditional WAFs (Cloudflare) are blind to semantic agent intents.

**AgentGate is an inline, sub-millisecond execution firewall that validates, sanitizes, or blocks tool payloads *before* they reach your execution plane.**

```
                 ┌─────────────────────────────────────────────────────────┐
                 │                 AUTONOMOUS AI AGENT                     │
                 │   (LangGraph / CrewAI / AutoGen / MCP / Claude / GPT)   │
                 └────────────────────────────┬────────────────────────────┘
                                              │  1. Tool Execution Call
                                              ▼
                 ┌─────────────────────────────────────────────────────────┐
                 │                 AGENTGATE AI FIREWALL                   │
                 │ ┌─────────────────────────────────────────────────────┐ │
                 │ │ ⚡ Sub-0.05ms Policy Engine (CEL & Rego Logic)      │ │
                 │ ├─────────────────────────────────────────────────────┤ │
                 │ │ 🛡️ Prompt Injection & Indirect Jailbreak Filter     │ │
                 │ ├─────────────────────────────────────────────────────┤ │
                 │ │ 🔒 Sensitive PII / PHI Token Masker & Redactor      │ │
                 │ ├─────────────────────────────────────────────────────┤ │
                 │ │ 🛑 Human-in-the-Loop (HITL) Smart Circuit Breaker   │ │
                 │ ├─────────────────────────────────────────────────────┤ │
                 │ │ 📜 Cryptographic Non-Repudiation Audit Ledger       │ │
                 │ └─────────────────────────────────────────────────────┘ │
                 └────────────────────────────┬────────────────────────────┘
                                              │  2. Deterministic Allowed Action
                                              ▼
                 ┌─────────────────────────────────────────────────────────┐
                 │               ENTERPRISE EXECUTION PLANE                │
                 │    (Production DBs, Stripe APIs, AWS IAM, Salesforce)   │
                 └─────────────────────────────────────────────────────────┘
```

---

## 🚀 Key Features

- **⚡ Sub-Millisecond Policy Engine:** Evaluates tool names, arguments, and parameter schemas with zero perceptible latency (< 0.05ms average).
- **🔒 Dynamic PII & Secret Redactor:** Luhn-validated Credit Card masking, US SSN redaction, and API token scrubbing (OpenAI, Stripe, AWS, JWT).
- **🛡️ Prompt Injection & Jailbreak Defense:** Detects indirect injection and adversarial evasion patterns inside tool parameters.
- **🛑 Human-in-the-Loop (HITL) Alerting:** Automatically pauses execution for high-stakes actions (e.g. `refund > $100` or `modify_iam_role`) and dispatches instant Telegram/Slack approval cards.
- **📜 Cryptographic Non-Repudiation Ledger:** Generates SHA-256 signed receipts for every evaluated action (EU AI Act & SOC2 audit ready).
- **🔌 Model Context Protocol (MCP) Proxy:** Native JSON-RPC proxy endpoint for Anthropic Claude and MCP-compatible agents.
- **🖥️ Built-in Web Console & Interactive Sandbox:** Real-time visual traffic stream, policy editor, and interactive attack simulation playground.

---

## 🏎️ Quickstart in 30 Seconds

### 1. Installation
```bash
git clone https://github.com/iamhariraj/agentgate.git
cd agentgate
pip install -r requirements.txt
```

### 2. Launch AgentGate Firewall & Web Dashboard
```bash
python -m agentgate.server
```
Open **`http://localhost:8765`** in your browser to view the live dashboard and interactive test playground!

### 3. Guard Agent Actions (Python SDK)
```python
from agentgate.client import AgentGateClient, AgentGateSecurityException

# Initialize Client
gate = AgentGateClient(gateway_url="http://localhost:8765")

# Example 1: Safe Action -> Returns clean, sanitized payload
clean_args = gate.guard_tool("search_kb", {"query": "return policy", "limit": 3})
print("Allowed:", clean_args)

# Example 2: Dangerous Action -> Raises Security Exception before execution
try:
    gate.guard_tool("execute_db", {"sql": "DROP TABLE users;"})
except AgentGateSecurityException as e:
    print("Shielded by AgentGate:", e)
```

---

## 🔌 Anthropic MCP Integration

AgentGate acts as a transparent JSON-RPC proxy for Anthropic's Model Context Protocol:

```bash
# Intercept and validate MCP tools/call requests
curl -X POST http://localhost:8765/v1/mcp/proxy \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {
      "name": "execute_database_query",
      "arguments": {"sql": "DROP TABLE users;"}
    }
  }'
```

**Response (Blocked in 0.03ms):**
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "error": {
    "code": -32000,
    "message": "AgentGate Security Block: Violation of policy 'Block Dangerous Database Writes' (ID: RULE-SQL-01): Detected restricted pattern 'drop table' in parameters."
  }
}
```

---

## 📊 Benchmarks

Benchmark results evaluated across 1,000 continuous evaluations on standard hardware:

| Metric | Result | Benchmark Target |
| :--- | :--- | :--- |
| **Mean Latency** | **0.047 ms** | Sub-5.0 ms SLA |
| **Median (p50)** | **0.015 ms** | Sub-1.0 ms |
| **99th Percentile (p99)** | **1.052 ms** | Sub-5.0 ms |
| **Throughput** | **21,000+ evals / sec** | High-concurrency ready |

To run the benchmarks locally:
```bash
python benchmarks/run_benchmark.py
```

---

## 🧪 Running the Test Suite

```bash
pytest tests/ -v
```

---

## 🐳 Docker Deployment

```bash
docker-compose up -d --build
```

---

## 📜 License

Licensed under the **Apache License, Version 2.0**. See [LICENSE](LICENSE) for details.
