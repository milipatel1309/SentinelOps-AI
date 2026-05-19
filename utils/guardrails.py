"""Safety guardrails for incident input and agent outputs."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


BLOCKED_PHRASES = [
    "ignore previous instructions",
    "bypass policy",
    "disable logging",
    "reveal secrets",
    "expose customer pii",
    "delete production database",
    "disable authentication",
    "escalate privileges",
    "ignore compliance rules",
    "ignore policies",
    "drop production",
    "exfiltrate",
    "disable audit",
]


@dataclass
class GuardrailResult:
    safe: bool
    blocked: bool
    reason: str | None
    matched_phrases: list[str]
    audit_entry: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "safe": self.safe,
            "blocked": self.blocked,
            "reason": self.reason,
            "matched_phrases": self.matched_phrases,
            "audit_entry": self.audit_entry,
        }


def check_guardrails(text: str, source: str = "user_input") -> GuardrailResult:
    """Scan text for unsafe phrases. Returns structured result."""
    normalized = (text or "").lower()
    matched = [p for p in BLOCKED_PHRASES if p in normalized]

    if matched:
        reason = (
            f"Blocked unsafe content from {source}: detected policy violations "
            f"({', '.join(matched)})."
        )
        audit_entry = {
            "event": "guardrail_block",
            "source": source,
            "matched_phrases": matched,
            "action": "workflow_stopped",
            "message": reason,
        }
        return GuardrailResult(
            safe=False,
            blocked=True,
            reason=reason,
            matched_phrases=matched,
            audit_entry=audit_entry,
        )

    return GuardrailResult(
        safe=True,
        blocked=False,
        reason=None,
        matched_phrases=[],
        audit_entry={
            "event": "guardrail_pass",
            "source": source,
            "action": "continue",
        },
    )
