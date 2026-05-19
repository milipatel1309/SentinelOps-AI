"""ComplianceAgent — policy checks, prompt injection detection, approvals."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from utils.guardrails import check_guardrails
from utils.llm_client import LLMClient

DATA_DIR = Path(__file__).resolve().parent.parent / "data"


class ComplianceAgent:
    name = "ComplianceAgent"

    def __init__(self, llm: LLMClient | None = None) -> None:
        self.llm = llm or LLMClient()
        self.rules = self._load_rules()

    def _load_rules(self) -> dict[str, Any]:
        path = DATA_DIR / "compliance_rules.json"
        with open(path, encoding="utf-8") as f:
            return json.load(f)

    def run(self, incident_text: str, intake: dict[str, Any]) -> dict[str, Any]:
        guard = check_guardrails(incident_text, source="compliance")
        text_lower = (incident_text or "").lower()

        blocked_actions: list[str] = []
        requires_approval: list[str] = []
        policy_violations: list[str] = []
        prompt_injection = False

        for phrase in self.rules.get("blocked_actions", []):
            if phrase.lower() in text_lower:
                blocked_actions.append(phrase)
                policy_violations.append(f"Blocked action requested: {phrase}")

        for phrase in self.rules.get("requires_approval", []):
            if phrase.lower() in text_lower:
                requires_approval.append(phrase)

        injection_patterns = [
            "ignore previous",
            "ignore all",
            "system prompt",
            "you are now",
            "jailbreak",
        ]
        if any(p in text_lower for p in injection_patterns):
            prompt_injection = True
            policy_violations.append("Potential prompt injection detected")

        blocked = guard.blocked or bool(blocked_actions) or prompt_injection
        safe = not blocked

        return {
            "agent": self.name,
            "status": "blocked" if blocked else "completed",
            "safe": safe,
            "blocked": blocked,
            "prompt_injection_detected": prompt_injection,
            "blocked_actions": blocked_actions,
            "requires_approval": requires_approval,
            "policy_violations": policy_violations,
            "guardrail": guard.to_dict(),
            "compliance_score": 0.0 if blocked else (0.85 if requires_approval else 0.95),
            "policy_reference": "incident_policy.md / compliance_rules.json",
            "summary": (
                "Compliance BLOCKED — unsafe request." if blocked
                else f"Compliance passed with {len(requires_approval)} actions requiring approval."
            ),
        }
