"""
PolicyEngine & Deterministic Action Firewall
Enforces parameter bounds, disallowed tools, SQL/Shell dangerous patterns, rate limits, and cryptographic receipt generation.
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

class FirewallDecision(BaseModel):
    decision_id: str
    timestamp: float
    tool_name: str
    action: RuleAction
    reason: str
    sanitized_args: Dict[str, Any]
    original_args: Dict[str, Any]
    evaluation_time_ms: float
    cryptographic_receipt: str
    risk_score: int = Field(ge=0, le=100)

class PolicyRule(BaseModel):
    id: str
    name: str
    description: str
    enabled: bool = True
    tool_pattern: str  # regex pattern or exact name or "*"
    action: RuleAction
    # Optional constraints
    max_amount: Optional[float] = None
    disallowed_keywords: List[str] = []
    required_keys: List[str] = []
    risk_score: int = 50

class PolicyEngine:
    def __init__(self, sanitizer: Optional[DataSanitizer] = None):
        self.sanitizer = sanitizer or DataSanitizer()
        self.rules: Dict[str, PolicyRule] = {}
        self.audit_log: List[FirewallDecision] = []
        self.rate_limiter: Dict[str, List[float]] = {}  # agent_id/session -> list of timestamps
        self.max_rate_per_sec = 10
        self.max_recursion_depth = 8
        self._load_default_rules()

    def _load_default_rules(self):
        """Loads default enterprise safety rules."""
        defaults = [
            PolicyRule(
                id="RULE-SQL-01",
                name="Block Dangerous Database Writes & Schema Alterations",
                description="Blocks raw SQL commands containing DROP, TRUNCATE, DELETE without WHERE, and ALTER TABLE.",
                tool_pattern=r"(?i).*(sql|database|query|db_execute).*",
                action=RuleAction.BLOCK,
                disallowed_keywords=["drop table", "drop database", "truncate table", "delete from", "alter table", "shutdown", "--", "; drop"],
                risk_score=95
            ),
            PolicyRule(
                id="RULE-SHELL-01",
                name="Block Destructive Shell Execution",
                description="Prevents agents from invoking raw terminal commands with dangerous system commands.",
                tool_pattern=r"(?i).*(bash|shell|terminal|exec_command|run_cmd).*",
                action=RuleAction.BLOCK,
                disallowed_keywords=["rm -rf", ":(){ :|:& };:", "mkfs", "dd if=/dev", "chmod -R 777 /", "> /dev/sda"],
                risk_score=100
            ),
            PolicyRule(
                id="RULE-FIN-01",
                name="Enforce Monetary Refund & Transfer Threshold",
                description="Requires Human-in-the-Loop (HITL) approval for any transaction or refund exceeding $100.00.",
                tool_pattern=r"(?i).*(refund|transfer|payout|stripe|wire|send_funds).*",
                action=RuleAction.REQUIRE_HITL,
                max_amount=100.0,
                risk_score=75
            ),
            PolicyRule(
                id="RULE-IAM-01",
                name="Block Privilege Escalation & IAM Role Modifications",
                description="Requires human approval when an agent modifies cloud security groups or user permissions.",
                tool_pattern=r"(?i).*(iam|permission|security_group|grant_role|add_admin).*",
                action=RuleAction.REQUIRE_HITL,
                disallowed_keywords=["AdministratorAccess", "*:*", "root", "sudoers"],
                risk_score=90
            ),
            PolicyRule(
                id="RULE-PII-01",
                name="Enforce Dynamic PII and Secret Redaction",
                description="Masks credit cards, SSNs, and API keys automatically across all tool parameters.",
                tool_pattern="*",
                action=RuleAction.MASK,
                risk_score=30
            )
        ]
        for rule in defaults:
            self.rules[rule.id] = rule

    def add_rule(self, rule: PolicyRule):
        self.rules[rule.id] = rule

    def toggle_rule(self, rule_id: str, enabled: bool) -> bool:
        if rule_id in self.rules:
            self.rules[rule_id].enabled = enabled
            return True
        return False

    def _check_rate_limit(self, session_id: str) -> bool:
        now = time.time()
        window = [t for t in self.rate_limiter.get(session_id, []) if now - t < 1.0]
        if len(window) >= self.max_rate_per_sec:
            return False  # rate limited
        window.append(now)
        self.rate_limiter[session_id] = window
        return True

    def _generate_receipt(self, tool_name: str, args: Dict[str, Any], action: str, timestamp: float) -> str:
        payload = f"{tool_name}:{json.dumps(args, sort_keys=True)}:{action}:{timestamp}"
        return hashlib.sha256(payload.encode('utf-8')).hexdigest()

    def evaluate(self, tool_name: str, tool_args: Dict[str, Any], session_id: str = "default_session", recursion_depth: int = 1) -> FirewallDecision:
        """
        Evaluates a tool call against active policy rules in sub-3ms latency.
        """
        start_time = time.perf_counter()
        now = time.time()
        decision_id = f"dec_{hashlib.md5(f'{now}:{tool_name}'.encode()).hexdigest()[:12]}"

        # 1. Check Recursion Loop Circuit Breaker
        if recursion_depth > self.max_recursion_depth:
            exec_time = (time.perf_counter() - start_time) * 1000.0
            receipt = self._generate_receipt(tool_name, tool_args, "BLOCK", now)
            decision = FirewallDecision(
                decision_id=decision_id,
                timestamp=now,
                tool_name=tool_name,
                action=RuleAction.BLOCK,
                reason=f"Circuit Breaker Triggered: Agent recursion depth ({recursion_depth}) exceeded maximum allowed limit ({self.max_recursion_depth}).",
                sanitized_args=tool_args,
                original_args=tool_args,
                evaluation_time_ms=exec_time,
                cryptographic_receipt=receipt,
                risk_score=100
            )
            self.audit_log.append(decision)
            return decision

        # 2. Check Velocity / Rate Limiter
        if not self._check_rate_limit(session_id):
            exec_time = (time.perf_counter() - start_time) * 1000.0
            receipt = self._generate_receipt(tool_name, tool_args, "BLOCK", now)
            decision = FirewallDecision(
                decision_id=decision_id,
                timestamp=now,
                tool_name=tool_name,
                action=RuleAction.BLOCK,
                reason=f"Circuit Breaker Triggered: Rate limit exceeded (> {self.max_rate_per_sec} tool calls/sec for session).",
                sanitized_args=tool_args,
                original_args=tool_args,
                evaluation_time_ms=exec_time,
                cryptographic_receipt=receipt,
                risk_score=90
            )
            self.audit_log.append(decision)
            return decision

        # 3. Dynamic Masking & Prompt Injection Sanitization
        sanitized_args, masks_count, has_injection = self.sanitizer.sanitize_payload(tool_args)

        if has_injection:
            exec_time = (time.perf_counter() - start_time) * 1000.0
            receipt = self._generate_receipt(tool_name, tool_args, "BLOCK", now)
            decision = FirewallDecision(
                decision_id=decision_id,
                timestamp=now,
                tool_name=tool_name,
                action=RuleAction.BLOCK,
                reason="Adversarial Prompt Injection or Jailbreak Pattern Detected in tool parameters.",
                sanitized_args=sanitized_args,
                original_args=tool_args,
                evaluation_time_ms=exec_time,
                cryptographic_receipt=receipt,
                risk_score=95
            )
            self.audit_log.append(decision)
            return decision

        # 4. Evaluate against Custom Policy Rules
        import re
        highest_risk = 0
        final_action = RuleAction.ALLOW
        reason = "All security policies satisfied. Execution approved."

        args_str = json.dumps(sanitized_args).lower()

        for rule in self.rules.values():
            if not rule.enabled:
                continue

            # Match tool pattern
            if rule.tool_pattern != "*" and not re.search(rule.tool_pattern, tool_name):
                continue

            # Disallowed keywords check
            for keyword in rule.disallowed_keywords:
                if keyword.lower() in args_str:
                    final_action = rule.action
                    highest_risk = max(highest_risk, rule.risk_score)
                    reason = f"Violation of policy '{rule.name}' (ID: {rule.id}): Detected restricted pattern '{keyword}' in parameters."
                    break

            if final_action == RuleAction.BLOCK:
                break

            # Maximum amount / financial threshold check
            if rule.max_amount is not None:
                # search for numeric amount fields
                for k, v in sanitized_args.items():
                    if any(sub in k.lower() for sub in ["amount", "value", "price", "funds", "total"]):
                        try:
                            val = float(v)
                            if val > rule.max_amount:
                                final_action = rule.action
                                highest_risk = max(highest_risk, rule.risk_score)
                                reason = f"Policy '{rule.name}' triggered: Amount (${val:.2f}) exceeds threshold (${rule.max_amount:.2f}). Requires Human-in-the-Loop verification."
                                break
                        except (ValueError, TypeError):
                            pass

        # If masks were applied and no blocking rule fired, mark as MASK
        if final_action == RuleAction.ALLOW and masks_count > 0:
            final_action = RuleAction.MASK
            reason = f"Execution approved with dynamic data masking ({masks_count} PII/Secret tokens redacted)."
            highest_risk = max(highest_risk, 30)

        exec_time = (time.perf_counter() - start_time) * 1000.0
        receipt = self._generate_receipt(tool_name, sanitized_args, final_action.value, now)

        decision = FirewallDecision(
            decision_id=decision_id,
            timestamp=now,
            tool_name=tool_name,
            action=final_action,
            reason=reason,
            sanitized_args=sanitized_args,
            original_args=tool_args,
            evaluation_time_ms=round(exec_time, 3),
            cryptographic_receipt=receipt,
            risk_score=highest_risk
        )

        self.audit_log.append(decision)
        return decision
