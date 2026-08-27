"""
AgentGate Concurrency & Multi-Worker Scaling Benchmark
Measures Throughput (RPS), Mean, p50, p95, and p99 latency across concurrent workers.
"""

import time
import statistics
import concurrent.futures
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from agentgate.engine import PolicyEngine

engine = PolicyEngine()

test_payloads = [
    ("execute_sql_query", {"query": "DROP TABLE users; SELECT * FROM data;"}),
    ("stripe_refund", {"customer_id": "cus_994", "amount": 45.0, "reason": "return"}),
    ("crm_update", {"name": "Test User", "card": "4532 0150 9988 1234", "api_key": "sk-live-1234567890abcdef"}),
    ("search_kb", {"query": "standard return policy", "limit": 5}),
    ("run_bash_cmd", {"command": "echo 'hello world'"})
]

def worker_task(num_requests: int, worker_id: int):
    lats = []
    for i in range(num_requests):
        tool, args = test_payloads[i % len(test_payloads)]
        t0 = time.perf_counter()
        engine.evaluate(tool, args, session_id=f"worker_{worker_id}_{i}")
        lats.append((time.perf_counter() - t0) * 1000.0) # in ms
    return lats

def test_concurrency(worker_counts = [1, 2, 4, 8, 16], requests_per_worker = 2500):
    print("🔥 AGENTGATE CONCURRENCY & SCALING BENCHMARK (1 vCPU AMD EPYC 7543P)")
    print("=" * 80)
    print(f"{'Workers':<9} | {'Total Requests':<15} | {'Throughput (RPS)':<18} | {'p50 (ms)':<10} | {'p99 (ms)':<10}")
    print("-" * 80)

    for w in worker_counts:
        total_reqs = w * requests_per_worker
        start_time = time.perf_counter()
        
        all_lats = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=w) as executor:
            futures = [executor.submit(worker_task, requests_per_worker, i) for i in range(w)]
            for f in concurrent.futures.as_completed(futures):
                all_lats.extend(f.result())
                
        total_duration = time.perf_counter() - start_time
        rps = total_reqs / total_duration
        p50 = statistics.median(all_lats)
        p99 = sorted(all_lats)[int(total_reqs * 0.99)]

        print(f"{w:<9} | {total_reqs:<15,} | {rps:<18,.1f} | {p50:<10.3f} | {p99:<10.3f}")

    print("=" * 80)

if __name__ == '__main__':
    test_concurrency()
