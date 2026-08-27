"""
PolicyEngine & Stateful Machine Authorization Engine
Enforces identity-based access control, cumulative state limits, parameter bounds,
and cryptographic non-repudiation machine-action receipts.
"""

import time
import hashlib
import json
from enum import Enum
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
from .sanitizer import DataSanitizer

class RuleAction(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    MASK = "MASK"
    REQUIRE_HITL = "REQUIRE_HITL"

class SessionState(BaseModel):
    session_id: str
    agent_id: str
    agent_role: str = "default_agent"
    cumulative_spend: float = 0.0
    action_count: int = 0
    accessed_tables: List[str] = []
    action_history: List[str] = []
    created_at: float = Field(default_factory=time.time)

class FirewallDecision(BaseModel):
    decision_id: str
    timestamp: float
    tool_name: str
    agent_id: str
    action: RuleAction
    reason: str
    sanitized_args: Dict[str, Any]
    original_args: Dict[str, Any]
    cumulative_session_spend: float
    evaluation_time_ms: float
    cryptographic_receipt: str
    risk_score: int = Field(ge=0, le=100)

class PolicyRule(BaseModel):
    id: str
    name: str
    description: str
    enabled: bool = True
    tool_pattern: str
    action: RuleAction
    allowed_roles: Optional[List[str]] = None
    max_amount_per_tx: Optional[float] = None
    max_cumulative_session_amount: Optional[float] = None
    disallowed_keywords: List[str] = []
    risk_score: int = 50

class PolicyEngine:
    def __init__(self, sanitizer: Optional[DataSanitizer] = None):
        self.sanitizer = sanitizer or DataSanitizer()
        self.rules: Dict[str, PolicyRule] = {}
        self.sessions: Dict[str, SessionState] = {}
        self.audit_log: List[FirewallDecision] = []
        self.rate_limiter: Dict[str, List[float]] = {}
        self.max_rate_per_sec = 15
        self.max_recursion_depth = 8
        self._load_default_rules()

    def _load_default_rules(self):
        defaults = [
            PolicyRule(
                id="RULE-AUTHZ-SQL-01",
                name="Prevent Schema Alterations & Unbounded Deletions",
                description="Deterministic ban on DDL SQL operations (DROP, TRUNCATE, ALTER).",
                tool_pattern=r"(?i).*(sql|database|query|db_execute).*",
                action=RuleAction.BLOCK,
                disallowed_keywords=["drop table", "drop database", "truncate table", "delete from", "alter table", "shutdown", "--", "; drop"],
                risk_score=95
            ),
            PolicyRule(
                id="RULE-AUTHZ-SHELL-01",
                name="Prevent Destructive Shell Command Execution",
                description="Deterministic ban on destructive system commands (rm -rf, mkfs, fork bombs).",
                tool_pattern=r"(?i).*(bash|shell|terminal|exec_command|run_cmd).*",
                action=RuleAction.BLOCK,
                disallowed_keywords=["rm -rf", ":(){ :|:& };:", "mkfs", "dd if=/dev", "chmod -R 777 /", "> /dev/sda"],
                risk_score=100
            ),
            PolicyRule(
                id="RULE-AUTHZ-FIN-01",
                name="Monetary Limits & Cumulative Session Cap",
                description="Enforces maximum $100 per refund and $500 cumulative limit per agent session.",
                tool_pattern=r"(?i).*(refund|transfer|payout|stripe|wire|send_funds).*",
                action=RuleAction.REQUIRE_HITL,
                allowed_roles=["SupportAgent_Tier1", "BillingManager", "admin"],
                max_amount_per_tx=100.0,
                max_cumulative_session_amount=500.0,
                risk_score=75
            ),
            PolicyRule(
                id="RULE-AUTHZ-IAM-01",
                name="Privilege Escalation Authorization Gate",
                description="Requires human escalation before assigning administrative IAM permissions.",
                tool_pattern=r"(?i).*(iam|permission|security_group|grant_role|add_admin).*",
                action=RuleAction.REQUIRE_HITL,
                disallowed_keywords=["AdministratorAccess", "*:*", "root", "sudoers"],
                risk_score=90
            ),
            PolicyRule(
                id="RULE-DLP-PII-01",
                name="Dynamic Data Loss Prevention & Secret Scrubbing",
                description="Zero-latency in-memory masking of Luhn credit cards, SSNs, and API keys.",
                tool_pattern="*",
                action=RuleAction.MASK,
                risk_score=30
            )
        ]
        for rule in defaults:
            self.rules[rule.id] = rule

    def get_or_create_session(self, session_id: str, agent_id: str, agent_role: str = "SupportAgent_Tier1") -> SessionState:
        if session_id not in self.sessions:
            self.sessions[session_id] = SessionState(session_id=session_id, agent_id=agent_id, agent_role=agent_role)
        return self.sessions[session_id]

    def _generate_receipt(self, tool_name: str, args: Dict[str, Any], action: str, timestamp: float, session: SessionState) -> str:
        payload = f"{session.agent_id}:{session.session_id}:{tool_name}:{json.dumps(args, sort_keys=True)}:{action}:{session.cumulative_spend}:{timestamp}"
        return hashlib.sha256(payload.encode('utf-8')).hexdigest()

    def evaluate(
        self,
        tool_name: str,
        tool_args: Dict[str, Any],
        session_id: str = "default_session",
        agent_id: str = "agent_default",
        agent_role: str = "SupportAgent_Tier1",
        recursion_depth: int = 1
    ) -> FirewallDecision:
        """
        Deterministic Authorization & State-Machine Policy Evaluation (< 0.1 ms).
        """
        start_time = time.perf_counter()
        now = time.time()
        decision_id = f"dec_{hashlib.md5(f'{now}:{tool_name}:{session_id}'.encode()).hexdigest()[:12]}"
        session = self.get_or_create_session(session_id, agent_id, agent_role)

        # 1. Check Recursion Loop Circuit Breaker
        if recursion_depth > self.max_recursion_depth:
            exec_time = (time.perf_counter() - start_time) * 1000.0
            receipt = self._generate_receipt(tool_name, tool_args, "BLOCK", now, session)
            decision = FirewallDecision(
                decision_id=decision_id,
                timestamp=now,
                tool_name=tool_name,
                agent_id=agent_id,
                action=RuleAction.BLOCK,
                reason=f"Swarm Recursion Brakes: Agent recursion depth ({recursion_depth}) exceeded maximum allowed limit ({self.max_recursion_depth}).",
                sanitized_args=tool_args,
                original_args=tool_args,
                cumulative_session_spend=session.cumulative_spend,
                evaluation_time_ms=round(exec_time, 3),
                cryptographic_receipt=receipt,
                risk_score=100
            )
            self.audit_log.append(decision)
            return decision

        # 2. Dynamic PII Masking & Injection Inspection
        sanitized_args, masks_count, has_injection = self.sanitizer.sanitize_payload(tool_args)

        if has_injection:
            exec_time = (time.perf_counter() - start_time) * 1000.0
            receipt = self._generate_receipt(tool_name, tool_args, "BLOCK", now, session)
            decision = FirewallDecision(
                decision_id=decision_id,
                timestamp=now,
                tool_name=tool_name,
                agent_id=agent_id,
                action=RuleAction.BLOCK,
                reason="Adversarial Injection Pattern detected in tool arguments.",
                sanitized_args=sanitized_args,
                original_args=tool_args,
                cumulative_session_spend=session.cumulative_spend,
                evaluation_time_ms=round(exec_time, 3),
                cryptographic_receipt=receipt,
                risk_score=95
            )
            self.audit_log.append(decision)
            return decision

        # 3. Policy Rule Evaluation (Role RBAC + Parameter Bounds + Cumulative State)
        import re
        highest_risk = 0
        final_action = RuleAction.ALLOW
        reason = "Authorized: All deterministic policies and state boundaries verified."
        tx_amount = 0.0

        # Extract transaction amount if present
        for k, v in sanitized_args.items():
            if any(sub in k.lower() for sub in ["amount", "value", "price", "funds", "total"]):
                try:
                    tx_amount = float(v)
                    break
                except (ValueError, TypeError):
                    pass

        args_str = json.dumps(sanitized_args).lower()

        for rule in self.rules.values():
            if not rule.enabled:
                continue

            if rule.tool_pattern != "*" and not re.search(rule.tool_pattern, tool_name):
                continue

            # Role RBAC Check
            if rule.allowed_roles and session.agent_role not in rule.allowed_roles:
                final_action = RuleAction.BLOCK
                highest_risk = max(highest_risk, 90)
                reason = f"RBAC Denied: Agent role '{session.agent_role}' is not authorized to execute tool '{tool_name}'."
                break

            # Disallowed Keyword Check
            for keyword in rule.disallowed_keywords:
                if keyword.lower() in args_str:
                    final_action = rule.action
                    highest_risk = max(highest_risk, rule.risk_score)
                    reason = f"Deterministic Policy Violation ({rule.id}): Detected restricted pattern '{keyword}'."
                    break

            if final_action == RuleAction.BLOCK:
                break

            # Single Transaction Threshold Check
            if rule.max_amount_per_tx is not None and tx_amount > rule.max_amount_per_tx:
                final_action = rule.action
                highest_risk = max(highest_risk, rule.risk_score)
                reason = f"Transaction Threshold Exceeded: Requested ${tx_amount:.2f} > allowed per-transaction cap (${rule.max_amount_per_tx:.2f})."

            # Cumulative Session Threshold Check
            if rule.max_cumulative_session_amount is not None:
                projected_spend = session.cumulative_spend + tx_amount
                if projected_spend > rule.max_cumulative_session_amount:
                    final_action = RuleAction.BLOCK
                    highest_risk = max(highest_risk, 85)
                    reason = f"Cumulative Session Limit Exceeded: Total session spend would reach ${projected_spend:.2f}, exceeding the allowed cap (${rule.max_cumulative_session_amount:.2f})."
                    break

        # If allowed and masks were applied
        if final_action == RuleAction.ALLOW and masks_count > 0:
            final_action = RuleAction.MASK
            reason = f"Authorized with DLP Masking: {masks_count} PII/Secret tokens redacted."
            highest_risk = max(highest_risk, 30)

        # Update Session State on Allow/Mask
        if final_action in [RuleAction.ALLOW, RuleAction.MASK]:
            session.cumulative_spend += tx_amount
            session.action_count += 1
            session.action_history.append(tool_name)

        exec_time = (time.perf_counter() - start_time) * 1000.0
        receipt = self._generate_receipt(tool_name, sanitized_args, final_action.value, now, session)

        decision = FirewallDecision(
            decision_id=decision_id,
            timestamp=now,
            tool_name=tool_name,
            agent_id=agent_id,
            action=final_action,
            reason=reason,
            sanitized_args=sanitized_args,
            original_args=tool_args,
            cumulative_session_spend=session.cumulative_spend,
            evaluation_time_ms=round(exec_time, 3),
            cryptographic_receipt=receipt,
            risk_score=highest_risk
        )

        self.audit_log.append(decision)
        return decision
