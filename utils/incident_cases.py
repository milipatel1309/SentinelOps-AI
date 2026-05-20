"""Multi-case incident registry, RBAC helpers, and live incident creation for demo UX."""

from __future__ import annotations

import copy
import json
from datetime import datetime
from pathlib import Path

from utils.demo_incident import get_demo_incident_result

_BASE = Path(__file__).resolve().parent.parent
_REGISTRY_PATH = _BASE / "data" / "demo_incidents.json"

CASE_STATUSES = frozenset(
    {"STANDBY", "ACTIVE", "UNDER REVIEW", "RESOLVED", "BLOCKED"}
)

COMMANDER_STATUSES = frozenset({"ACTIVE", "UNDER REVIEW"})
COMPLIANCE_STATUSES = frozenset({"RESOLVED", "BLOCKED", "UNDER REVIEW"})

STATUS_TO_UI_KEY = {
    "STANDBY": "standby",
    "ACTIVE": "active",
    "UNDER REVIEW": "under_review",
    "RESOLVED": "resolved",
    "BLOCKED": "blocked",
}

from utils.access_control import (
    ALL_ROLES,
    ROLE_PERMISSIONS,
    allowed_roles_label,
    can_access_page_with_elevation,
)


DEMO_ANALYSTS = (
    {"name": "Jordan Lee", "team": "SOC Analyst Team"},
    {"name": "Alex Chen", "team": "SOC Analyst Team"},
    {"name": "Sam Rivera", "team": "SOC Analyst Team"},
    {"name": "Morgan Blake", "team": "SOC Analyst Team"},
)


def can_access_page(role: str, page: str) -> bool:
    """Return True if the demo role may open this page (includes temporary elevation)."""
    return can_access_page_with_elevation(role, page)


def role_can_run_analysis(role: str) -> bool:
    return role in ("SOC Analyst", "SOC Manager")


def role_can_create_incident(role: str) -> bool:
    return role in ("SOC Analyst", "SOC Manager")


def role_can_approve_remediation(role: str) -> bool:
    return role in ("Incident Commander", "SOC Manager")


def role_can_use_manager_tools(role: str) -> bool:
    """Approve, reject, assign, and escalate on SOC Command Center."""
    return role == "SOC Manager"


def role_is_observer(role: str) -> bool:
    return role == "Observer"


def role_is_read_only_operations(role: str) -> bool:
    """Read-only on investigation and command views (no run / approve / assign)."""
    return role in ("Observer", "Compliance Reviewer")


def load_incident_registry() -> list[dict]:
    """Return deep copies of all demo incidents from JSON."""
    data = json.loads(_REGISTRY_PATH.read_text(encoding="utf-8"))
    return copy.deepcopy(data["incidents"])


def filter_incidents_for_role(role: str, incidents: list[dict]) -> list[dict]:
    """Filter incident queue by demo role workspace."""
    if role == "SOC Manager":
        return list(incidents)
    if role == "Incident Commander":
        return [i for i in incidents if i.get("status") in COMMANDER_STATUSES]
    if role == "Compliance Reviewer":
        return [i for i in incidents if i.get("status") in COMPLIANCE_STATUSES]
    return list(incidents)


def filter_incidents_by_title(incidents: list[dict], query: str) -> list[dict]:
    if not query.strip():
        return incidents
    q = query.strip().lower()
    return [i for i in incidents if q in (i.get("title") or "").lower()]


def get_incident_by_id(incidents: list[dict], incident_id: str) -> dict | None:
    for inc in incidents:
        if inc.get("incident_id") == incident_id:
            return inc
    return None


def _parse_incident_numeric_id(raw: str) -> int:
    if not raw.startswith("INC-"):
        return 0
    parts = raw.split("-")
    if len(parts) >= 2 and parts[-1].isdigit():
        return int(parts[-1])
    return 0


def next_incident_id(incidents: list[dict]) -> str:
    """Next live incident id: INC-2026-{counter:04d} from max existing numeric suffix."""
    max_num = 0
    for inc in incidents:
        max_num = max(max_num, _parse_incident_numeric_id(inc.get("incident_id", "")))
    return f"INC-2026-{max_num + 1:04d}"


def format_incident_timestamps(dt: datetime | None = None) -> dict:
    """
  Local timestamps for live incidents.

  Returns created_date (May 18, 2026), created_day (Monday), created_time (10:45 PM),
  created_display, last_updated fields, and open_for duration string.
  """
    now = dt or datetime.now()
    created_date = now.strftime("%B %d, %Y")
    if created_date.startswith("0"):
        created_date = created_date.replace(" 0", " ", 1)
    day = now.strftime("%A")
    time_12h = now.strftime("%I:%M %p").lstrip("0")
    iso_local = now.isoformat(timespec="seconds")
    display = f"{created_date} · {time_12h}"
    return {
        "created_date": created_date,
        "created_day": day,
        "created_time": time_12h,
        "created_display": display,
        "last_updated": iso_local,
        "last_updated_display": display,
        "open_for": "0m",
    }


def _title_from_text(incident_text: str) -> str:
    first = (incident_text or "").strip().split("\n")[0].strip()
    if not first:
        return "New incident"
    return first[:80] + ("…" if len(first) > 80 else "")


def _workflow_state_from_result(result: dict) -> str:
    if result.get("blocked") or result.get("compliance", {}).get("blocked"):
        return "guardrail_blocked"
    if result.get("compliance", {}).get("requires_approval"):
        return "remediation_pending_approval"
    intake = result.get("intake", {})
    if intake.get("guardrail", {}).get("blocked"):
        return "guardrail_blocked"
    return "active_investigation"


def _status_from_result(result: dict) -> str:
    if result.get("blocked") or result.get("compliance", {}).get("blocked"):
        return "BLOCKED"
    if result.get("intake", {}).get("guardrail", {}).get("blocked"):
        return "BLOCKED"
    return "ACTIVE"


def create_live_incident(
    incident_text: str,
    incidents: list[dict],
    *,
    created_by: str = "SOC Analyst",
) -> dict:
    """Create an ACTIVE registry row before orchestrator completes."""
    ts = format_incident_timestamps()
    title = _title_from_text(incident_text)
    return {
        "incident_id": next_incident_id(incidents),
        "title": title,
        "status": "ACTIVE",
        "severity": "MEDIUM",
        "created_date": ts["created_date"],
        "created_day": ts["created_day"],
        "created_time": ts["created_time"],
        "created_display": ts["created_display"],
        "last_updated": ts["last_updated"],
        "last_updated_display": ts["last_updated_display"],
        "resolved_date": None,
        "resolved_display": None,
        "duration_open": ts["open_for"],
        "duration_review": None,
        "owner": "soc-analyst-live",
        "owner_role": created_by,
        "assigned_team": "SOC Analyst Team",
        "created_by": created_by,
        "affected_services": [],
        "risk_score": 0,
        "confidence": 0,
        "approval_required": False,
        "pending_rollback": False,
        "workflow_state": "intake",
        "short_summary": incident_text[:160] if incident_text else "Live intake in progress.",
        "incident_text": incident_text,
        "compliance_result": "PENDING",
        "auditor_notes": "",
        "payload_key": "custom",
        "audit_timeline": [
            {
                "time": ts["last_updated_display"],
                "event": "Live incident created — analysis started",
                "actor": created_by,
            }
        ],
        "policy_violations": [],
        "approval_history": [],
    }


def apply_result_to_incident(incident: dict, result: dict) -> None:
    """Merge orchestrator output into a registry incident row."""
    ts = format_incident_timestamps()
    incident["last_updated"] = ts["last_updated"]
    incident["last_updated_display"] = ts["last_updated_display"]
    incident["status"] = _status_from_result(result)
    intake = result.get("intake", {})
    auditor = result.get("auditor", {})
    compliance = result.get("compliance", {})

    if intake.get("severity"):
        incident["severity"] = intake["severity"]
    if intake.get("affected_services"):
        incident["affected_services"] = list(intake["affected_services"])
    if intake.get("summary"):
        incident["short_summary"] = intake["summary"][:200]
    if auditor.get("risk_score") is not None:
        incident["risk_score"] = auditor["risk_score"]
    if auditor.get("confidence_score") is not None:
        incident["confidence"] = auditor["confidence_score"]
    if auditor.get("executive_summary"):
        incident["auditor_notes"] = auditor["executive_summary"][:240]

    incident["approval_required"] = bool(
        compliance.get("requires_approval")
        or any(
            a.get("requires_approval") or a.get("human_approval_required")
            for a in (result.get("remediation") or {}).get("actions", [])
        )
    )
    incident["workflow_state"] = _workflow_state_from_result(result)

    if incident["status"] == "BLOCKED":
        incident["compliance_result"] = "BLOCKED"
        incident["policy_violations"] = list(compliance.get("policy_violations", []))
    elif compliance.get("safe") is False:
        incident["compliance_result"] = "FAILED"
    else:
        incident["compliance_result"] = "PASSED"

    incident["audit_timeline"].append(
        {
            "time": ts["last_updated_display"],
            "event": f"Analysis complete — status {incident['status']}",
            "actor": "SentinelOrchestrator",
        }
    )


def _ensure_pending_actions(incident: dict) -> list[dict]:
    """Return pending_actions list, synthesizing from approval flags when missing."""
    existing = incident.get("pending_actions")
    if existing is not None:
        return list(existing)
    derived: list[dict] = []
    if not incident.get("approval_required"):
        return derived
    iid = incident.get("incident_id", "INC-?")
    for idx, hist in enumerate(incident.get("approval_history") or []):
        if hist.get("status") != "pending":
            continue
        derived.append(
            {
                "id": f"PA-{iid}-{idx + 1}",
                "type": "Remediation",
                "description": hist.get("action", "Pending remediation"),
                "severity": incident.get("severity", "MEDIUM"),
                "status": "pending",
                "requested_by": incident.get("created_by", "SOC Analyst"),
            }
        )
    if not derived and incident.get("approval_required"):
        derived.append(
            {
                "id": f"PA-{iid}-1",
                "type": "Remediation",
                "description": incident.get("short_summary", "Remediation approval required"),
                "severity": incident.get("severity", "MEDIUM"),
                "status": "pending",
                "requested_by": incident.get("owner_role", "SOC Analyst"),
            }
        )
    incident["pending_actions"] = derived
    return derived


def is_compliance_blocked(incident_id: str, incidents: list[dict]) -> bool:
    """True when guardrails or compliance block manager override."""
    inc = get_incident_by_id(incidents, incident_id)
    if not inc:
        return True
    if inc.get("status") == "BLOCKED":
        return True
    if inc.get("compliance_result") == "BLOCKED":
        return True
    payload = get_payload_for_incident(inc)
    if payload.get("blocked"):
        return True
    comp = payload.get("compliance") or {}
    if comp.get("blocked"):
        return True
    intake = payload.get("intake", {}).get("guardrail") or {}
    if intake.get("blocked"):
        return True
    return False


def get_pending_actions_for_manager(incidents: list[dict]) -> list[dict]:
    """Flatten pending manager approval rows across the fleet."""
    rows: list[dict] = []
    for inc in incidents:
        if inc.get("status") == "RESOLVED":
            continue
        for action in _ensure_pending_actions(inc):
            if action.get("status") != "pending":
                continue
            rows.append(
                {
                    "incident_id": inc.get("incident_id"),
                    "title": inc.get("title"),
                    "action_id": action.get("id"),
                    "action_type": action.get("type", "Remediation"),
                    "description": action.get("description", ""),
                    "severity": action.get("severity", inc.get("severity", "—")),
                    "requested_by": action.get("requested_by", inc.get("created_by", "—")),
                    "status": action.get("status", "pending"),
                    "incident_status": inc.get("status"),
                }
            )
    return rows


def _append_audit(incident: dict, event: str, actor: str = "SOC Manager") -> None:
    ts = format_incident_timestamps()
    incident["last_updated"] = ts["last_updated"]
    incident["last_updated_display"] = ts["last_updated_display"]
    incident.setdefault("audit_timeline", []).append(
        {"time": ts["last_updated_display"], "event": event, "actor": actor}
    )


def _sync_approval_flags(incident: dict) -> None:
    """Reconcile approval_required and workflow_state after manager action."""
    actions = _ensure_pending_actions(incident)
    pending = [a for a in actions if a.get("status") == "pending"]
    rejected = any(a.get("status") == "rejected" for a in actions)
    incident["approval_required"] = bool(pending)
    if pending:
        incident["workflow_state"] = "remediation_pending_approval"
        if incident.get("status") not in ("BLOCKED", "RESOLVED"):
            incident["status"] = "UNDER REVIEW"
    elif rejected and incident.get("status") not in ("BLOCKED", "RESOLVED", "STANDBY"):
        incident["status"] = "UNDER REVIEW"
        incident["workflow_state"] = "under_manager_review"
    elif incident.get("status") not in ("BLOCKED", "RESOLVED", "STANDBY"):
        incident["workflow_state"] = "active_investigation"
        incident["status"] = "ACTIVE"


def manager_approve(incidents: list[dict], incident_id: str, action_id: str) -> tuple[bool, str]:
    """Approve a pending action; returns (ok, message)."""
    if is_compliance_blocked(incident_id, incidents):
        return False, "compliance_blocked"
    inc = get_incident_by_id(incidents, incident_id)
    if not inc:
        return False, "not_found"
    actions = _ensure_pending_actions(inc)
    target = next((a for a in actions if a.get("id") == action_id), None)
    if not target or target.get("status") != "pending":
        return False, "not_pending"
    target["status"] = "approved"
    target["approval_status"] = "approved"
    for hist in inc.get("approval_history") or []:
        if hist.get("status") == "pending":
            hist["status"] = "approved"
            hist["approver"] = "SOC Manager"
            ts = format_incident_timestamps()
            hist["time"] = ts["last_updated_display"]
    still_pending = any(a.get("status") == "pending" for a in actions)
    if still_pending:
        inc["status"] = "UNDER REVIEW"
        inc["workflow_state"] = "remediation_pending_approval"
    else:
        inc["status"] = "ACTIVE"
        inc["workflow_state"] = "active_investigation"
        inc["approval_required"] = False
    _append_audit(inc, f"Approved action {action_id}")
    _sync_approval_flags(inc)
    return True, "approved"


def manager_reject(incidents: list[dict], incident_id: str, action_id: str) -> tuple[bool, str]:
    """Reject a pending action; returns (ok, message)."""
    if is_compliance_blocked(incident_id, incidents):
        return False, "compliance_blocked"
    inc = get_incident_by_id(incidents, incident_id)
    if not inc:
        return False, "not_found"
    actions = _ensure_pending_actions(inc)
    target = next((a for a in actions if a.get("id") == action_id), None)
    if not target or target.get("status") != "pending":
        return False, "not_pending"
    target["status"] = "rejected"
    target["approval_status"] = "rejected"
    for hist in inc.get("approval_history") or []:
        if hist.get("status") == "pending":
            hist["status"] = "rejected"
            hist["approver"] = "SOC Manager"
    inc["status"] = "UNDER REVIEW"
    inc["workflow_state"] = "rollback_review" if inc.get("pending_rollback") else "under_manager_review"
    _append_audit(inc, f"Rejected action {action_id}")
    _sync_approval_flags(inc)
    return True, "rejected"


def approve_action(incidents: list[dict], incident_id: str, action_id: str) -> tuple[bool, str]:
    """Alias for manager_approve (session-state demo API)."""
    return manager_approve(incidents, incident_id, action_id)


def reject_action(incidents: list[dict], incident_id: str, action_id: str) -> tuple[bool, str]:
    """Alias for manager_reject (session-state demo API)."""
    return manager_reject(incidents, incident_id, action_id)


def assign_incident(incidents: list[dict], incident_id: str, analyst_name: str) -> bool:
    """Assign incident to a demo analyst."""
    inc = get_incident_by_id(incidents, incident_id)
    if not inc:
        return False
    inc["assigned_analyst"] = analyst_name
    inc["assigned_team"] = "SOC Analyst Team"
    _append_audit(inc, f"Assigned to {analyst_name}")
    return True


def escalate_incident(incidents: list[dict], incident_id: str) -> bool:
    """Escalate case to Incident Commander — UNDER REVIEW + audit entry."""
    inc = get_incident_by_id(incidents, incident_id)
    if not inc or is_compliance_blocked(incident_id, incidents):
        return False
    inc["owner_role"] = "Incident Commander"
    inc["assigned_team"] = "Command Center Alpha"
    inc["status"] = "UNDER REVIEW"
    inc["workflow_state"] = "commander_escalation"
    _append_audit(inc, "Escalated to Incident Commander")
    return True


def analyst_activity_panel(incidents: list[dict]) -> list[dict]:
    """Demo analyst roster with open-case counts and last activity."""
    counts: dict[str, int] = {a["name"]: 0 for a in DEMO_ANALYSTS}
    last_activity: dict[str, str] = {}
    for inc in incidents:
        if inc.get("status") not in ("ACTIVE", "UNDER REVIEW", "STANDBY"):
            continue
        name = inc.get("assigned_analyst")
        if not name:
            continue
        counts[name] = counts.get(name, 0) + 1
        last_activity[name] = inc.get("last_updated_display", "—")
    rows = []
    for analyst in DEMO_ANALYSTS:
        name = analyst["name"]
        rows.append(
            {
                "Analyst": name,
                "Team": analyst["team"],
                "Open cases": counts.get(name, 0),
                "Last activity": last_activity.get(name, "—"),
            }
        )
    return rows


def demo_analyst_names() -> list[str]:
    return [a["name"] for a in DEMO_ANALYSTS]


def manager_metrics(incidents: list[dict]) -> dict:
    """KPI aggregates for SOC Command Center."""
    today = datetime.now().strftime("%B %d, %Y")
    status_counts = {s: 0 for s in ("ACTIVE", "UNDER REVIEW", "BLOCKED", "RESOLVED")}
    for inc in incidents:
        st = inc.get("status")
        if st in status_counts:
            status_counts[st] += 1

    owners_analyst: set[str] = set()
    owners_commander: set[str] = set()
    owners_reviewer: set[str] = set()
    for inc in incidents:
        role = inc.get("owner_role") or ""
        team = inc.get("assigned_team") or inc.get("owner", "")
        label = team or role
        if inc.get("assigned_analyst"):
            owners_analyst.add(inc["assigned_analyst"])
        elif "Analyst" in role or "analyst" in (inc.get("owner") or ""):
            owners_analyst.add(label)
        elif "Commander" in role or "commander" in (inc.get("owner") or ""):
            owners_commander.add(label)
        elif "Compliance" in role or "Reviewer" in role:
            owners_reviewer.add(label)

    pending_queue = len(get_pending_actions_for_manager(incidents))
    pending_approvals = sum(1 for i in incidents if i.get("approval_required"))
    new_today = sum(1 for i in incidents if i.get("created_date") == today)
    fleet_active_pending = status_counts["ACTIVE"] + status_counts["UNDER REVIEW"] + pending_queue

    return {
        "active_count": status_counts["ACTIVE"],
        "under_review_count": status_counts["UNDER REVIEW"],
        "blocked_count": status_counts["BLOCKED"],
        "resolved_count": status_counts["RESOLVED"],
        "pending_approvals": pending_approvals,
        "pending_action_count": pending_queue,
        "fleet_active_pending": fleet_active_pending,
        "new_today": new_today,
        "assigned_analysts": sorted(owners_analyst) or ["SOC Analyst Team"],
        "assigned_commanders": sorted(owners_commander) or ["Incident Commander Pool"],
        "assigned_reviewers": sorted(owners_reviewer) or ["Compliance Review Board"],
        "queue_analyst": len(filter_incidents_for_role("SOC Analyst", incidents)),
        "queue_commander": len(filter_incidents_for_role("Incident Commander", incidents)),
        "queue_compliance": len(filter_incidents_for_role("Compliance Reviewer", incidents)),
    }


def _minimal_payload(
    incident_text: str,
    *,
    severity: str,
    services: list[str],
    blocked: bool = False,
    resolved: bool = False,
    requires_approval: bool = False,
    risk_score: int = 70,
    confidence: int = 85,
    summary: str = "",
) -> dict:
    """Build orchestrator-shaped payload for cases without full JSON."""
    intake_blocked = blocked
    compliance_blocked = blocked
    compliance_status = "blocked" if blocked else "completed"
    intake_status = "blocked" if blocked else "completed"
    remediation_actions = []
    if requires_approval and not blocked:
        remediation_actions = [
            {
                "step": "Approve scaling change",
                "requires_approval": True,
                "human_approval_required": True,
                "execution_status": "pending_human_approval",
            }
        ]
    payload = {
        "blocked": blocked,
        "incident_text": incident_text,
        "intake": {
            "agent": "IntakeAgent",
            "status": intake_status,
            "intent": "security_incident" if blocked else "performance_degradation",
            "entities": services,
            "affected_services": services,
            "severity": severity,
            "guardrail": {
                "safe": not blocked,
                "blocked": intake_blocked,
                "reason": "Destructive action blocked" if blocked else None,
                "matched_phrases": ["delete production"] if blocked else [],
            },
            "summary": summary or f"Incident affecting {', '.join(services)} at {severity} severity.",
        },
        "planner": {"agent": "PlannerAgent", "status": "completed" if not blocked else "skipped"},
        "log_analysis": {
            "agent": "LogAnalysisAgent",
            "status": "completed" if not blocked else "skipped",
            "anomalies": [],
            "summary": "Telemetry analyzed." if not blocked else "Skipped — workflow blocked.",
        },
        "compliance": {
            "agent": "ComplianceAgent",
            "status": compliance_status,
            "safe": not blocked,
            "blocked": compliance_blocked,
            "requires_approval": requires_approval,
            "summary": "Blocked by policy." if blocked else "Compliance review complete.",
        },
        "rca": {
            "agent": "RootCauseAgent",
            "status": "completed" if resolved or (not blocked and severity != "CRITICAL") else "completed",
            "root_cause": summary[:120] if summary else "Under investigation",
            "summary": summary or "Root cause analysis complete.",
        },
        "remediation": {
            "agent": "RemediationAgent",
            "status": "completed" if not blocked else "blocked",
            "actions": remediation_actions,
        },
        "auditor": {
            "agent": "AuditorAgent",
            "status": "completed",
            "risk_score": risk_score,
            "confidence_score": confidence,
            "executive_summary": summary or incident_text[:200],
        },
        "audit_trail": [
            {
                "timestamp": "2026-05-18T14:00:00+00:00",
                "step": "IntakeAgent",
                "status": intake_status,
                "detail": summary or incident_text[:120],
            }
        ],
    }
    if blocked:
        payload["intake"]["guardrail"]["audit_entry"] = {
            "event": "guardrail_block",
            "source": "intake",
            "action": "halt",
        }
    return payload


def get_payload_for_incident(incident: dict) -> dict:
    """Return investigation payload for a registry incident."""
    key = incident.get("payload_key", "")
    text = incident.get("incident_text", "")
    severity = incident.get("severity", "MEDIUM")
    services = incident.get("affected_services", [])
    summary = incident.get("short_summary", "")

    if key == "payment_api":
        payload = get_demo_incident_result()
        payload["incident_text"] = text
        return payload

    if key == "unsafe_delete":
        return _minimal_payload(
            text,
            severity=severity,
            services=services,
            blocked=True,
            risk_score=incident.get("risk_score", 99),
            confidence=incident.get("confidence", 98),
            summary=summary,
        )

    if key == "privilege_escalation":
        return _minimal_payload(
            text,
            severity=severity,
            services=services,
            resolved=True,
            risk_score=incident.get("risk_score", 76),
            confidence=incident.get("confidence", 91),
            summary=summary,
        )

    if key == "auth_outage":
        p = _minimal_payload(
            text,
            severity=severity,
            services=services,
            requires_approval=True,
            risk_score=incident.get("risk_score", 94),
            confidence=incident.get("confidence", 89),
            summary=summary,
        )
        p["remediation"]["actions"].append(
            {
                "step": "Rollback AuthService to v2.14.2",
                "requires_approval": True,
                "human_approval_required": True,
                "execution_status": "pending_human_approval",
            }
        )
        return p

    if key == "database_cpu":
        p = get_demo_incident_result()
        p = copy.deepcopy(p)
        p["incident_text"] = text
        p["intake"]["affected_services"] = services
        p["intake"]["severity"] = severity
        p["intake"]["summary"] = summary
        p["auditor"]["risk_score"] = incident.get("risk_score", 91)
        p["auditor"]["confidence_score"] = incident.get("confidence", 87)
        if incident.get("approval_required"):
            for action in p.get("remediation", {}).get("actions", [])[:2]:
                action["requires_approval"] = True
                action["human_approval_required"] = True
                action["execution_status"] = "pending_human_approval"
        return p

    return _minimal_payload(
        text,
        severity=severity,
        services=services or ["UnknownService"],
        requires_approval=bool(incident.get("approval_required")),
        risk_score=incident.get("risk_score", 50),
        confidence=incident.get("confidence", 80),
        summary=summary,
    )


def ui_status_key(case_status: str) -> str:
    """Map registry status enum to get_incident_status() key."""
    return STATUS_TO_UI_KEY.get(case_status, "standby")


def first_active_incident(incidents: list[dict]) -> dict | None:
    for inc in incidents:
        if inc.get("status") == "ACTIVE":
            return inc
    return incidents[0] if incidents else None


def commander_metrics(incidents: list[dict]) -> dict:
    """Aggregate KPIs for Active Operations dashboard."""
    active = [i for i in incidents if i.get("status") in COMMANDER_STATUSES]
    critical = [i for i in active if i.get("severity") == "CRITICAL"]
    pending_approvals = sum(1 for i in active if i.get("approval_required"))
    rollbacks = sum(1 for i in active if i.get("pending_rollback"))
    services: set[str] = set()
    for i in active:
        services.update(i.get("affected_services") or [])
    return {
        "active_count": len(active),
        "critical_count": len(critical),
        "pending_approvals": pending_approvals,
        "services_impacted": len(services),
        "rollback_pending": rollbacks,
        "degraded_services": len(services),
    }


def create_standby_incident(
    title: str,
    incident_text: str,
    owner: str = "soc-analyst-01",
    *,
    created_by: str = "SOC Analyst",
) -> dict:
    """New incident row for analyst intake."""
    ts = format_incident_timestamps()
    return {
        "incident_id": "",
        "title": title or "New incident",
        "status": "STANDBY",
        "severity": "MEDIUM",
        "created_date": ts["created_date"],
        "created_day": ts["created_day"],
        "created_time": ts["created_time"],
        "created_display": ts["created_display"],
        "last_updated": ts["last_updated"],
        "last_updated_display": ts["last_updated_display"],
        "resolved_date": None,
        "resolved_display": None,
        "duration_open": ts["open_for"],
        "duration_review": None,
        "owner": owner,
        "owner_role": created_by,
        "assigned_team": "SOC Analyst Team",
        "created_by": created_by,
        "affected_services": [],
        "risk_score": 0,
        "confidence": 0,
        "approval_required": False,
        "pending_rollback": False,
        "workflow_state": "intake",
        "short_summary": incident_text[:160] if incident_text else "Awaiting analysis.",
        "incident_text": incident_text,
        "compliance_result": "PENDING",
        "auditor_notes": "",
        "payload_key": "custom",
        "audit_timeline": [
            {
                "time": ts["last_updated_display"],
                "event": "Incident created",
                "actor": created_by,
            }
        ],
        "policy_violations": [],
        "approval_history": [],
    }


def queue_rows_for_role(role: str, incidents: list[dict]) -> list[dict]:
    """Build role-specific queue table rows."""
    rows: list[dict] = []
    for inc in incidents:
        if role == "SOC Analyst":
            rows.append(
                {
                    "Incident ID": inc.get("incident_id"),
                    "Title": inc.get("title"),
                    "Severity": inc.get("severity"),
                    "Status": inc.get("status"),
                    "Created Date": inc.get("created_date", inc.get("created_display")),
                    "Created Day": inc.get("created_day", "—"),
                    "Created Time": inc.get("created_time", "—"),
                    "Last Updated": inc.get("last_updated_display"),
                }
            )
        elif role == "Incident Commander":
            rows.append(
                {
                    "Incident ID": inc.get("incident_id"),
                    "Title": inc.get("title"),
                    "Severity": inc.get("severity"),
                    "Status": inc.get("status"),
                    "Affected Services": ", ".join(inc.get("affected_services") or []) or "—",
                    "Approval Required": "Yes" if inc.get("approval_required") else "No",
                    "Open Duration": inc.get("duration_open", "—"),
                }
            )
        elif role == "Compliance Reviewer":
            rows.append(
                {
                    "Incident ID": inc.get("incident_id"),
                    "Title": inc.get("title"),
                    "Status": inc.get("status"),
                    "Compliance Result": inc.get("compliance_result"),
                    "Policy Violations": len(inc.get("policy_violations") or []),
                    "Created Date": inc.get("created_date", inc.get("created_display")),
                    "Resolved/Review Date": inc.get("resolved_display") or "—",
                }
            )
        elif role == "SOC Manager":
            rows.append(
                {
                    "Incident ID": inc.get("incident_id"),
                    "Title": inc.get("title"),
                    "Status": inc.get("status"),
                    "Severity": inc.get("severity"),
                    "Owner Role": inc.get("owner_role", "—"),
                    "Assigned Team": inc.get("assigned_team", "—"),
                    "Created Date": inc.get("created_date", inc.get("created_display")),
                    "Last Updated": inc.get("last_updated_display"),
                    "Current Stage": inc.get("workflow_state", "—"),
                }
            )
    return rows


def open_incident_button_label(role: str) -> str:
    labels = {
        "SOC Analyst": "Open Investigation",
        "Incident Commander": "Open Incident",
        "Compliance Reviewer": "Open Audit",
        "SOC Manager": "Open Case",
    }
    return labels.get(role, "Open")
