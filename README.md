<div align="center">

# 🛡️ Lakshman Rekha (लक्ष्मण रेखा)
### The Inviolable Authorization Boundary & State Control Plane for Autonomous AI Agents

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python Version](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-blue)](https://www.python.org/)
[![Decision Latency](https://img.shields.io/badge/Decision%20Latency-%3C%200.1ms-emerald.svg)](#benchmarks)
[![Throughput](https://img.shields.io/badge/Throughput-9%2C000%2B%20RPS%2Fcore-indigo.svg)](#benchmarks)
[![Security Standard](https://img.shields.io/badge/Security-Machine%20Transaction%20AuthZ-orange.svg)](#the-authorization-gap)

**"Identity tells you who the machine is. Permissions tell you what it can access. Lakshman Rekha defines the line it can never cross."**

[The Authorization Gap](#the-authorization-gap) • [Flagship Demos](#-flagship-demos) • [Architecture](#architecture) • [Quickstart](#quickstart-in-30-seconds) • [Benchmarks](#benchmarks) • [MCP Proxy](#anthropic-model-context-protocol-mcp-integration)

</div>

---

## ⚡ The Category Wedge: The Autonomous Authorization Gap

Traditional security models fail when applied to autonomous AI agents because they answer the wrong questions:
- **Traditional IAM (Okta, CyberArk):** Answers *"Who is the agent?"* and *"What static resources can it access?"* (Blind to cumulative financial transactions and runtime parameters).
- **API Gateways & WAFs (Cloudflare, Kong):** Answers *"Is the HTTP payload syntactically valid?"* (Blind to multi-turn agent state and MCP JSON-RPC schemas).
- **LLM Guardrails (Llama Guard, NeMo):** Answers *"Does this text sound malicious?"* (Fuzzy, non-deterministic, and incurs a 300ms–800ms latency penalty).

**Lakshman Rekha answers the only question that matters for autonomous systems:**
> *"Regardless of what the model reasons, is this exact transaction authorized given the agent's identity, delegation chain, cumulative session state, and organizational boundary policies?"*

### 📊 The Category Authorization Gap Matrix

| Security Dimension | Standard IAM | API Gateway / WAF | LLM Guardrails | **Lakshman Rekha** |
| :--- | :---: | :---: | :---: | :---: |
| **Agent Machine Identity** | ✅ Yes | ❌ No | ❌ No | **✅ Native** |
| **Static Tool Allow/Deny** | ⚠️ Partial | ⚠️ Partial | ❌ No | **✅ Native** |
| **Deterministic Parameter Bounds** (e.g. $100 cap) | ❌ No | ⚠️ Partial | ❌ No (Fuzzy) | **✅ Native (< 0.1ms)** |
| **Cumulative Session Spend Cap** (e.g. $500 total) | ❌ No | ❌ No | ❌ No | **✅ Native** |
| **Slow-Drip Data Exfiltration Detection** | ❌ No | ❌ No | ❌ No | **✅ Native** |
| **Swarm Recursion Brakes** (Loop Caps) | ❌ No | ⚠️ Partial | ⚠️ Partial | **✅ Native** |
| **Zero LLM Latency Tax** (< 0.1ms overhead) | ✅ Yes | ✅ Yes | ❌ No (300-800ms) | **✅ Native (< 0.1ms)** |
| **Action Evidence Ledger** (Cryptographic Non-Repudiation) | ⚠️ Partial | ⚠️ Partial | ❌ No | **✅ SHA-256 Receipts** |

---

## 🎯 Flagship Demos

### Demo 1: Stateful Cumulative Transaction Authorization
An agent with role `SupportAgent_Tier1` has permission to refund customers up to **$100 per transaction** and **$500 cumulative per session**.

```
[Action 1] Refund $80  ──▶ ✅ ALLOWED (Session Total: $80 / $500)
[Action 2] Refund $90  ──▶ ✅ ALLOWED (Session Total: $170 / $500)
[Action 3] Refund $95  ──▶ ✅ ALLOWED (Session Total: $265 / $500)
[Action 4] Refund $90  ──▶ ✅ ALLOWED (Session Total: $355 / $500)
[Action 5] Refund $160 ──▶ 🛑 BLOCKED (Single cap > $100 & pushes session to $515 > $500)
[Action 6] Refund $80  ──▶ ✅ ALLOWED (Session Total: $435 / $500)
[Action 7] Refund $70  ──▶ 🛑 BLOCKED (Cumulative cap breach: $435 + $70 = $505 > $500)
```
Run this live: `python examples/stateful_authorization_demo.py`

---

### Demo 2: The "Slow-Drip" Exfiltration Interception
An agent reads individual customer records one-by-one (50 records) and subsequently attempts to execute `export_data_to_external_sftp`.
- **Stateless WAF / IAM:** Allows the export because the export tool is on the agent's allowlist.
- **Lakshman Rekha:** Evaluates the session state (`records_accessed == 50`) and **BLOCKS the export in 0.18 ms** with cryptographic proof.

Run this live: `python examples/slow_drip_exfiltration_demo.py`

---

## 🏛️ Architecture: The Dual-Path Control Plane

```
                          AUTONOMOUS AI AGENT / MCP CLIENT
                                         │
                                         ▼
                     ┌───────────────────────────────────────┐
                     │         LAKSHMAN REKHA KERNEL         │
                     │  (Identity, Session Context & State)  │
                     └───────────────────┬───────────────────┘
                                         │
                 ┌───────────────────────┴───────────────────────┐
                 ▼                                               ▼
     ┌────────────────────────┐                     ┌────────────────────────┐
     │ ⚡ FAST-PATH ENGINE     │                     │ 🧠 DEEP INTELLIGENCE   │
     │   (< 0.1 ms Latency)   │                     │   (Asynchronous/Deep)  │
     ├────────────────────────┤                     ├────────────────────────┤
     │ • Role & Tool RBAC     │                     │ • Swarm collusion      │
     │ • Parameter Bounds     │                     │ • Behavioral drift     │
     │ • Cumulative State     │                     │ • Semantic anomaly     │
     │   (Spend, Records Read)│                     │ • Injection classifier │
     │ • PII/DLP Token Redact │                     └───────────┬────────────┘
     │ • State Machine Graph  │                                 │
     └───────────┬────────────┘                                 │
                 │                                              │
                 └───────────────────────┬──────────────────────┘
                                         ▼
                             FINAL VERDICT & STATE UPDATE
                        [ ALLOW | BLOCK | ESCALATE_HITL ]
                                         │
                                         ▼
                     ┌───────────────────────────────────────┐
                     │  📜 ACTION EVIDENCE LEDGER            │
                     │  (SHA-256 Cryptographic Receipts)     │
                     └───────────────────────────────────────┘
```

---

## 🏎️ Quickstart in 30 Seconds

### 1. Installation
```bash
git clone https://github.com/harirajrathod/lakshman-rekha.git
cd lakshman-rekha
pip install -r requirements.txt
```

### 2. Launch the Firewall Server & Dashboard
```bash
python -m agentgate.server
```
Open **`http://localhost:8765`** in your browser.

### 3. Guard Agent Actions (Python SDK)
```python
from agentgate.client import AgentGateClient, AgentGateSecurityException

rekha = AgentGateClient(gateway_url="http://localhost:8765")

# Guard an action against identity + cumulative state limits
try:
    clean_args = rekha.guard_tool(
        tool_name="stripe_issue_refund",
        tool_args={"customer_id": "cus_982", "amount": 85.00},
        session_id="sess_support_99"
    )
    print("Allowed:", clean_args)
except AgentGateSecurityException as e:
    print("Boundary Enforced:", e)
```

---

## 🔌 Anthropic Model Context Protocol (MCP) Integration

Lakshman Rekha operates as a native pre-execution proxy for MCP:

```bash
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

---

## 📊 Scientific Benchmarks & Empirical Honesty

Tested on 1 vCPU AMD EPYC 7543P @ 2.0GHz across 25,000 continuous evaluations:

- **Mean Evaluation Latency:** **0.043 ms** (43 microseconds)
- **Median (p50):** **0.018 ms** (18 microseconds)
- **p99 Latency (Single Thread):** **1.066 ms**

### Concurrency Load Scaling (1 vCPU Core)

| Workers | Total Requests | Throughput (RPS) | p50 (ms) | p99 (ms) | Takeaway |
| :---: | :---: | :---: | :---: | :---: | :--- |
| **1 Worker** | 2,500 | **6,970 req/sec** | **0.073 ms** | **1.299 ms** | Baseline optimal |
| **2 Workers** | 5,000 | **9,213 req/sec** | **0.073 ms** | **6.782 ms** | Peak single-core throughput |
| **4 Workers** | 10,000 | **7,984 req/sec** | **0.074 ms** | **19.609 ms** | CPU context switching |
| **8 Workers** | 20,000 | **8,361 req/sec** | **0.075 ms** | **25.706 ms** | Thread queue contention |

> **Systems Note:** Median latency remains flat at ~73 µs across all concurrency levels. On a single physical core, scaling threads beyond 2 workers increases tail latency (p99) due to Python GIL / thread context switching.

---

## 📜 License

Licensed under the **Apache License, Version 2.0**. See [LICENSE](LICENSE) for details.
