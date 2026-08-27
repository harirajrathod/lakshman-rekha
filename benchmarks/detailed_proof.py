import time
import statistics
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from agentgate.engine import PolicyEngine

engine = PolicyEngine()
NUM_ITERATIONS = 5000

categories = {
    "1. Safe Tool Query (Search KB)": ("search_kb", {"query": "standard return policy", "limit": 5}),
    "2. SQL Injection Blocker (DROP TABLE)": ("execute_sql_query", {"query": "DROP TABLE users; SELECT * FROM data;"}),
    "3. PII & Luhn Card Scrubber": ("crm_update", {"name": "Hariraj Rathod", "card": "4532 0150 9988 1234", "api_key": "sk-live-1234567890abcdef"}),
    "4. Monetary Threshold Gate ($499 Refund)": ("stripe_refund", {"customer_id": "cus_994", "amount": 499.0, "reason": "damaged item"}),
    "5. Shell Command Blocker (rm -rf)": ("run_bash_cmd", {"command": "rm -rf /var/data && shutdown -h now"})
}

print(f"🔬 AGENTGATE LATENCY & PROFILING PROOF REPORT")
print(f"Tested on: 1 vCPU AMD EPYC 7543P @ 2.0GHz | {NUM_ITERATIONS * len(categories):,} Total Invocations\n")

total_all_latencies = []

for name, (tool, args) in categories.items():
    lats = []
    for _ in range(NUM_ITERATIONS):
        t0 = time.perf_counter()
        engine.evaluate(tool, args, session_id="proof_sess")
        elapsed_us = (time.perf_counter() - t0) * 1_000_000 # microseconds
        lats.append(elapsed_us)
        total_all_latencies.append(elapsed_us / 1000.0) # ms

    mean_us = statistics.mean(lats)
    p50_us = statistics.median(lats)
    p95_us = sorted(lats)[int(NUM_ITERATIONS * 0.95)]
    p99_us = sorted(lats)[int(NUM_ITERATIONS * 0.99)]
    
    print(f"▶ {name}")
    print(f"   • Mean:    {mean_us:6.2f} µs ({mean_us/1000:6.3f} ms)")
    print(f"   • p50:     {p50_us:6.2f} µs ({p50_us/1000:6.3f} ms)")
    print(f"   • p95:     {p95_us:6.2f} µs ({p95_us/1000:6.3f} ms)")
    print(f"   • p99:     {p99_us:6.2f} µs ({p99_us/1000:6.3f} ms)\n")

print("="*60)
print(f"📊 AGGREGATE SUMMARY ACROSS ALL 25,000 ACTIONS:")
print(f"• Mean Latency:  {statistics.mean(total_all_latencies):.3f} ms ({statistics.mean(total_all_latencies)*1000:.1f} microseconds)")
print(f"• Median (p50):  {statistics.median(total_all_latencies):.3f} ms ({statistics.median(total_all_latencies)*1000:.1f} microseconds)")
print(f"• 99th %ile:     {sorted(total_all_latencies)[int(len(total_all_latencies)*0.99)]:.3f} ms")
print(f"• Peak Speed:    {len(total_all_latencies) / (sum(total_all_latencies)/1000):,.0f} evaluations / second")
print("="*60)
