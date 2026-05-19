"""Prebuilt enterprise incident payload for role-based demo UX."""

from __future__ import annotations

import copy
import json
from pathlib import Path

_PAYLOAD_PATH = Path(__file__).resolve().parent / "demo_incident_payload.json"

# Aligns with preset 1 (Payment API / failed logins) plus database scope.
DEMO_INCIDENT_TEXT = (
    "Payment API showing elevated p99 latency above 1s and AuthService "
    "reporting a spike in failed logins during peak checkout hours. "
    "Database connection pool saturation observed."
)

DEMO_PRELOAD_ROLES = frozenset({"Incident Commander", "Compliance Reviewer"})


def get_demo_incident_result() -> dict:
    """Return a deep copy of the orchestrator-shaped investigation payload."""
    data = json.loads(_PAYLOAD_PATH.read_text(encoding="utf-8"))
    return copy.deepcopy(data)


def should_preload_demo_for_role(role: str | None) -> bool:
    return role in DEMO_PRELOAD_ROLES


def get_preload_incident_id(role: str | None) -> str | None:
    """Default registry incident to preload per role."""
    if role == "Incident Commander":
        return "INC-001"
    if role == "Compliance Reviewer":
        return "INC-003"
    return None
