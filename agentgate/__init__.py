"""
AgentGate AI — The Zero-Trust Policy Engine & Real-Time Action Firewall for Autonomous AI Agents.
"""

__version__ = "1.0.0"
__author__ = "AgentGate AI Team"

from .engine import PolicyEngine, FirewallDecision, RuleAction
from .sanitizer import DataSanitizer
from .hitl import HITLManager
from .client import AgentGateClient

__all__ = [
    "PolicyEngine",
    "FirewallDecision",
    "RuleAction",
    "DataSanitizer",
    "HITLManager",
    "AgentGateClient",
]
