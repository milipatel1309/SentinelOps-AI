"""Standard agent output metadata for workflow UI and expanders."""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any

# Pipeline display order (key, label, orchestrator agent id)
PIPELINE_AGENTS: list[tuple[str, str, str]] = [
    ("intake", "Intake", "IntakeAgent"),
    ("planner", "Planner", "PlannerAgent"),
    ("log_analysis", "Log Analysis", "LogAnalysisAgent"),
    ("compliance", "Compliance", "ComplianceAgent"),
    ("rca", "Root Cause", "RootCauseAgent"),
    ("remediation", "Remediation", "RemediationAgent"),
    ("validation", "Validation", "ValidationAgent"),
    ("auditor", "Auditor", "AuditorAgent"),
]

AGENT_ID_TO_KEY = {agent_id: key for key, _label, agent_id in PIPELINE_AGENTS}


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso_ts(dt: datetime | None = None) -> str:
    return (dt or utc_now()).isoformat()


def _deterministic_float(seed: str, low: float, high: float) -> float:
    h = hashlib.sha256(seed.encode()).hexdigest()
    n = int(h[:8], 16) / 0xFFFFFFFF
    return low + (high - low) * n


def _default_duration_ms(agent_id: str) -> float:
    base = {"IntakeAgent": 420, "PlannerAgent": 680, "LogAnalysisAgent": 1240}
    base.update(
        {
            "ComplianceAgent": 890,
            "RootCauseAgent": 1560,
            "RemediationAgent": 1120,
            "ValidationAgent": 640,
            "AuditorAgent": 740,
        }
    )
    jitter = _deterministic_float(agent_id, -80, 120)
    return base.get(agent_id, 900) + jitter


def enrich_agent_output(
    data: dict[str, Any],
    *,
    agent_id: str,
    started_at: datetime | None = None,
    completed_at: datetime | None = None,
    duration_ms: float | None = None,
) -> dict[str, Any]:
    """Ensure structured detail fields exist on agent result dicts."""
    if not data:
        return data

    started = started_at or utc_now()
    completed = completed_at or utc_now()
    duration = duration_ms if duration_ms is not None else _default_duration_ms(agent_id)

    seed = f"{agent_id}:{data.get('summary', '')}"
    conf = data.get("confidence")
    if conf is None:
        if "compliance_score" in data:
            conf = float(data["compliance_score"])
        elif "confidence_score" in data:
            conf = float(data["confidence_score"]) / 100.0
        else:
            conf = _deterministic_float(seed, 0.72, 0.94)

    findings = data.get("findings")
    if not findings:
        findings = _build_findings(agent_id, data)

    reasoning = data.get("reasoning")
    if not reasoning:
        reasoning = _build_reasoning(agent_id, data)

    evidence = data.get("evidence_analyzed")
    if evidence is None:
        evidence = _build_evidence_analyzed(agent_id, data)

    actions = data.get("actions_taken")
    if actions is None:
        actions = _build_actions_taken(agent_id, data)

    data.setdefault("started_at", iso_ts(started))
    data.setdefault("completed_at", iso_ts(completed))
    data.setdefault("execution_duration_ms", round(duration, 1))
    data.setdefault("confidence", round(float(conf), 3) if conf <= 1 else round(float(conf) / 100.0, 3))
    data.setdefault("findings", findings)
    data.setdefault("reasoning", reasoning)
    data.setdefault("evidence_analyzed", evidence)
    data.setdefault("actions_taken", actions)
    return data


def _build_findings(agent_id: str, data: dict[str, Any]) -> list[str]:
    if agent_id == "IntakeAgent":
        return [
            data.get("summary", "Incident parsed"),
            f"Severity: {data.get('severity', 'UNKNOWN')}",
            f"Services: {', '.join(data.get('affected_services', []))}",
        ]
    if agent_id == "PlannerAgent":
        return [data.get("plan_summary", "Execution plan ready")] + [
            f"Task {t.get('id')}: {t.get('description')}" for t in data.get("tasks", [])[:4]
        ]
    if agent_id == "LogAnalysisAgent":
        return [data.get("summary", "")] + [
            f"{a.get('service', a.get('event_type', '?'))}: {a.get('metric', a.get('type', ''))}"
            for a in data.get("anomalies", [])[:5]
        ]
    if agent_id == "ComplianceAgent":
        items = [data.get("summary", "Policy evaluation complete")]
        items.extend(data.get("policy_violations", [])[:4])
        return items
    if agent_id == "RootCauseAgent":
        return [data.get("root_cause", data.get("summary", ""))] + data.get(
            "contributing_factors", []
        )[:3]
    if agent_id == "RemediationAgent":
        return [a.get("action", "") for a in data.get("actions", [])[:5]] or [
            data.get("summary", "No remediation steps")
        ]
    if agent_id == "ValidationAgent":
        items = [data.get("summary", "Validation complete")]
        items.extend(data.get("high_risk_matches", [])[:4])
        return items
    if agent_id == "AuditorAgent":
        return [
            data.get("executive_summary", "")[:200],
            f"Risk score: {data.get('risk_score', '—')}",
        ]
    return [data.get("summary", "Analysis complete")]


def _build_reasoning(agent_id: str, data: dict[str, Any]) -> str:
    templates = {
        "IntakeAgent": (
            "Classified intent from keywords and entity extraction; severity inferred from "
            "incident language and guardrail signals."
        ),
        "PlannerAgent": (
            "Built parallel/sequential task graph based on severity and affected services."
        ),
        "LogAnalysisAgent": (
            "Filtered cloud and security telemetry by service scope; flagged threshold breaches."
        ),
        "ComplianceAgent": (
            "Matched request against compliance_rules.json and injection patterns; "
            "enforced approval requirements."
        ),
        "RootCauseAgent": (
            "Correlated anomalies with incident keywords using rule-based RCA; "
            "confidence weighted by evidence density."
        ),
        "RemediationAgent": (
            "Generated least-privilege remediation steps; high-risk actions flagged for approval."
        ),
        "ValidationAgent": (
            "Scanned remediation narrative for destructive or policy-bypass language; "
            "set approval flags when high-risk phrases appear."
        ),
        "AuditorAgent": (
            "Aggregated agent outputs into risk/confidence scores and executive narrative."
        ),
    }
    extra = data.get("summary", "")
    base = templates.get(agent_id, "Deterministic mock reasoning for demo orchestration.")
    return f"{base} {extra}".strip()


def _build_evidence_analyzed(agent_id: str, data: dict[str, Any]) -> list[str]:
    if agent_id == "LogAnalysisAgent":
        ev = list(data.get("evidence", []))
        ev.append(
            f"Cloud rows: {data.get('cloud_log_rows_analyzed', 0)}; "
            f"Security events: {data.get('security_events_analyzed', 0)}"
        )
        return ev
    if agent_id == "RootCauseAgent":
        return list(data.get("evidence_refs", []))
    if agent_id == "ComplianceAgent":
        return [data.get("policy_reference", "incident_policy.md")]
    if agent_id == "IntakeAgent":
        return list(data.get("entities", [])) + list(data.get("keywords", []))
    if agent_id == "RemediationAgent":
        return data.get("rollback_plan", [])
    return [data.get("summary", "Structured agent output")]


def _build_actions_taken(agent_id: str, data: dict[str, Any]) -> list[str]:
    status = data.get("status", "")
    if status in ("skipped", "halted"):
        return [data.get("reason", data.get("summary", "Agent skipped in workflow"))]
    if agent_id == "IntakeAgent":
        g = data.get("guardrail", {})
        return ["Guardrail scan"] + ([f"Blocked: {g.get('reason')}"] if g.get("blocked") else ["Intake accepted"])
    if agent_id == "ComplianceAgent" and data.get("blocked"):
        return ["Workflow halt triggered", "Audit entry recorded"]
    if agent_id == "RemediationAgent":
        return [f"Step {a.get('step')}: {a.get('action')}" for a in data.get("actions", [])[:6]]
    if agent_id == "AuditorAgent":
        return ["Final report compiled", "Audit trail sealed"]
    return [f"Status: {status}", data.get("summary", "Completed agent pass")]


def normalize_status(raw: str | None, *, blocked: bool = False) -> str:
    """Map agent statuses to pipeline UI states."""
    if blocked or raw in ("blocked",):
        return "blocked"
    if raw in ("completed",):
        return "completed"
    if raw in ("running",):
        return "running"
    if raw in ("skipped", "halted", "partial", "n/a", None, ""):
        return "pending"
    return raw if raw in ("pending", "running", "completed", "blocked") else "pending"


def build_pipeline_status(result: dict[str, Any]) -> list[dict[str, Any]]:
    """Ordered pipeline nodes with final status per agent (deduped)."""
    ws = result.get("workflow_status", [])
    by_id: dict[str, dict[str, Any]] = {}
    for item in ws:
        agent_id = item.get("agent", "")
        by_id[agent_id] = item  # last wins

    nodes: list[dict[str, Any]] = []
    for key, label, agent_id in PIPELINE_AGENTS:
        data = result.get(key) or {}
        wf = by_id.get(agent_id, {})
        raw = wf.get("status") or data.get("status", "pending")
        blocked = bool(data.get("blocked")) or raw == "blocked"
        status = normalize_status(raw, blocked=blocked)
        nodes.append(
            {
                "key": key,
                "label": label,
                "agent_id": agent_id,
                "status": status,
                "detail": wf.get("detail", data.get("summary", "")),
                "data": data,
            }
        )
    return nodes


def workflow_status_final(workflow: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    """Serialize orchestrator workflow dict to ordered list."""
    out: list[dict[str, Any]] = []
    for _key, label, agent_id in PIPELINE_AGENTS:
        entry = workflow.get(agent_id)
        if entry:
            out.append(
                {
                    "agent": agent_id,
                    "label": label,
                    "status": entry.get("status", "pending"),
                    "detail": entry.get("detail", ""),
                }
            )
    return out
