"""
AgentGate Killer Demo: Stateful Cumulative Authorization
Demonstrates machine IAM enforcement over an agent issuing multiple transactions within a session.
"""

import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from agentgate.engine import PolicyEngine, RuleAction

def run_stateful_demo():
    engine = PolicyEngine()
    
    agent_id = "agent_cs_tier1_492"
    session_id = "sess_customer_88192"
    agent_role = "SupportAgent_Tier1"

    print("=" * 80)
    print("🤖 AGENTGATE STATEFUL AUTHORIZATION & MACHINE IAM DEMO")
    print(f"• Agent ID:   {agent_id} (Role: {agent_role})")
    print(f"• Session ID: {session_id}")
    print(f"• Policy:     Single Refund Cap: $100.00 | Cumulative Session Cap: $500.00")
    print("=" * 80)

    transactions = [
        {"desc": "Valid Refund #1", "amount": 80.0, "cust": "cus_01"},
        {"desc": "Valid Refund #2", "amount": 90.0, "cust": "cus_02"},
        {"desc": "Valid Refund #3", "amount": 95.0, "cust": "cus_03"},
        {"desc": "Valid Refund #4", "amount": 90.0, "cust": "cus_04"},
        {"desc": "Malicious / Rogue Refund ($160 single amount)", "amount": 160.0, "cust": "cus_attacker"},
        {"desc": "Session-Exhausting Refund (Valid $80, but pushes cumulative to $435)", "amount": 80.0, "cust": "cus_05"},
        {"desc": "Session-Breaching Refund ($70, would reach $505 > $500 cap)", "amount": 70.0, "cust": "cus_06"},
    ]

    for i, tx in enumerate(transactions, start=1):
        payload = {"customer_id": tx["cust"], "amount": tx["amount"], "reason": "Customer complaint"}
        
        dec = engine.evaluate(
            tool_name="stripe_issue_refund",
            tool_args=payload,
            session_id=session_id,
            agent_id=agent_id,
            agent_role=agent_role
        )

        status_icon = "✅ ALLOWED" if dec.action == RuleAction.ALLOW else "🛑 BLOCKED" if dec.action == RuleAction.BLOCK else "⚠️ " + dec.action.value
        print(f"\n[Step {i}] {tx['desc']}")
        print(f"  • Attempted Amount:  ${tx['amount']:.2f}")
        print(f"  • Verdict:           {status_icon} (in {dec.evaluation_time_ms} ms)")
        print(f"  • Reason:            {dec.reason}")
        print(f"  • Cumulative Spend:  ${dec.cumulative_session_spend:.2f} / $500.00")
        print(f"  • Evidence Receipt:  SHA-256 [{dec.cryptographic_receipt[:16]}...]")

    print("\n" + "=" * 80)
    print("🎯 DEMO RESULT: Machine state boundaries deterministically prevented overspending.")
    print("=" * 80)

if __name__ == '__main__':
    run_stateful_demo()
