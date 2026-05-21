"""Safety guardrails for incident input and agent outputs."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

# Output filtering patterns (PII / secrets redaction before UI display)
_EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
_PHONE_RE = re.compile(r"(?<!\d)(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}(?!\d)")
_SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_API_KEY_RE = re.compile(
    r"\b(?:sk-[a-zA-Z0-9]{20,}|grok_[a-zA-Z0-9]{20,}|"
    r"api[_-]?key[=:\s]+[a-zA-Z0-9_-]{16,})\b",
    re.IGNORECASE,
)


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


def validate_llm_output(output_text: str) -> dict[str, Any]:
    """
    Sanitize LLM-generated text before display.

    Returns sanitized_output, violations list, and risk_level (low | medium | high).
    Redacts emails, phone numbers, SSNs, and API key-like tokens.
    """
    text = output_text or ""
    violations: list[str] = []
    sanitized = text

    if _EMAIL_RE.search(sanitized):
        violations.append("email_address")
        sanitized = _EMAIL_RE.sub("[REDACTED_EMAIL]", sanitized)
    if _PHONE_RE.search(sanitized):
        violations.append("phone_number")
        sanitized = _PHONE_RE.sub("[REDACTED_PHONE]", sanitized)
    if _SSN_RE.search(sanitized):
        violations.append("ssn")
        sanitized = _SSN_RE.sub("[REDACTED_SSN]", sanitized)
    if _API_KEY_RE.search(sanitized):
        violations.append("api_key")
        sanitized = _API_KEY_RE.sub("[REDACTED_SECRET]", sanitized)

    if len(violations) >= 2:
        risk_level = "high"
    elif violations:
        risk_level = "medium"
    else:
        risk_level = "low"

    return {
        "sanitized_output": sanitized,
        "violations": violations,
        "risk_level": risk_level,
    }
