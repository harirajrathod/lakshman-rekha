"""
HITLManager (Human-in-the-Loop Approval Gate)
Manages pending high-risk agent actions and sends real-time approval requests to Telegram / Slack / Webhook.
"""

import os
import time
import requests
from typing import Dict, Any, Optional
from pydantic import BaseModel

class PendingAction(BaseModel):
    action_id: str
    tool_name: str
    tool_args: Dict[str, Any]
    reason: str
    risk_score: int
    created_at: float
    status: str = "PENDING"  # PENDING, APPROVED, REJECTED
    resolved_by: Optional[str] = None
    resolved_at: Optional[float] = None

class HITLManager:
    def __init__(self, telegram_token: Optional[str] = None, telegram_chat_id: Optional[str] = None):
        self.telegram_token = telegram_token or os.getenv("TELEGRAM_BOT_TOKEN")
        self.telegram_chat_id = telegram_chat_id or os.getenv("TELEGRAM_CHAT_ID")
        self.pending_actions: Dict[str, PendingAction] = {}

    def request_approval(self, decision_id: str, tool_name: str, tool_args: Dict[str, Any], reason: str, risk_score: int) -> PendingAction:
        """Registers a pending action and dispatches Telegram notification if configured."""
        pending = PendingAction(
            action_id=decision_id,
            tool_name=tool_name,
            tool_args=tool_args,
            reason=reason,
            risk_score=risk_score,
            created_at=time.time(),
            status="PENDING"
        )
        self.pending_actions[decision_id] = pending
        self._notify_telegram(pending)
        return pending

    def resolve_action(self, action_id: str, approved: bool, user: str = "admin") -> Optional[PendingAction]:
        """Approves or rejects a pending action."""
        if action_id not in self.pending_actions:
            return None
        action = self.pending_actions[action_id]
        action.status = "APPROVED" if approved else "REJECTED"
        action.resolved_by = user
        action.resolved_at = time.time()
        return action

    def _notify_telegram(self, action: PendingAction):
        """Sends an urgent notification to Telegram."""
        if not self.telegram_token or not self.telegram_chat_id:
            return
        
        msg = (
            f"🚨 *AgentGate Security Alert: Action Paused*\n\n"
            f"• *Tool:* `{action.tool_name}`\n"
            f"• *Risk Score:* `{action.risk_score}/100`\n"
            f"• *Reason:* {action.reason}\n"
            f"• *Parameters:* ```json\n{action.tool_args}\n```\n"
            f"• *Action ID:* `{action.action_id}`\n\n"
            f"⚠️ *Decision Required:* Action is paused waiting for human review."
        )
        try:
            requests.post(
                f"https://api.telegram.org/bot{self.telegram_token}/sendMessage",
                json={
                    "chat_id": self.telegram_chat_id,
                    "text": msg,
                    "parse_mode": "Markdown"
                },
                timeout=3.0
            )
        except Exception as e:
            # Non-blocking log
            print(f"[AgentGate HITL] Telegram notification error: {e}")
