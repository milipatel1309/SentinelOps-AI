"""ValidationAgent — post-remediation safety review before audit."""

from __future__ import annotations

import re
from typing import Any

HIGH_RISK_PATTERNS: list[tuple[str, str]] = [
    (r"\bdelete\b", "delete"),
    (r"\bdisable\b", "disable"),
    (r"\bpurge\b", "purge"),
    (r"\bshutdown\b", "shutdown"),
    (r"\bbypass\b", "bypass"),
    (r"expose\s+secrets?", "expose secrets"),
    (r"\bpii\b", "PII"),
    (r"\bfirewall\b", "firewall"),
    (r"rollback\s+production", "rollback production"),
    (r"drop\s+database", "drop database"),
]


class ValidationAgent:
    name = "ValidationAgent"

    def run(
        self,
        remediation: dict[str, Any],
        context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Review remediation output; flag high-risk language and approval needs."""
        _ = context  # shared orchestration context (incident_text, prior agent outputs)

        if remediation.get("blocked") or remediation.get("status") == "skipped":
            return {
                "agent": self.name,
                "status": "skipped",
                "validation_status": "skipped",
                "confidence_score": 0.0,
                "requires_approval": False,
                "high_risk_matches": [],
                "summary": "Validation skipped — remediation not produced.",
            }

        corpus = self._remediation_corpus(remediation)
        matches = self._scan_high_risk(corpus)
        action_approvals = any(
            a.get("requires_approval") or a.get("human_approval_required")
            for a in remediation.get("actions", [])
        )
        requires_approval = bool(matches) or action_approvals

        if matches:
            validation_status = "warning"
            confidence = max(0.35, 0.85 - 0.08 * len(matches))
        else:
            validation_status = "passed"
            confidence = 0.92 if not requires_approval else 0.78

        summary = (
            f"Remediation validation {validation_status}: "
            f"{len(matches)} high-risk phrase(s) in plan."
            if matches
            else (
                "Remediation validation passed — no blocked phrases detected."
                + (" Human approval still required on flagged steps." if requires_approval else "")
            )
        )

        return {
            "agent": self.name,
            "status": "completed",
            "validation_status": validation_status,
            "confidence_score": round(confidence, 3),
            "requires_approval": requires_approval,
            "high_risk_matches": matches,
            "summary": summary,
        }

    @staticmethod
    def _remediation_corpus(remediation: dict[str, Any]) -> str:
        parts = [remediation.get("summary", "")]
        for action in remediation.get("actions", []):
            parts.append(str(action.get("action", "")))
        parts.extend(remediation.get("rollback_plan", []))
        return " ".join(p for p in parts if p).lower()

    @staticmethod
    def _scan_high_risk(text: str) -> list[str]:
        found: list[str] = []
        for pattern, label in HIGH_RISK_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                found.append(label)
        return found
