"""Session-scoped RBAC, role navigation, and temporary access elevation (demo only)."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

import streamlit as st

ALL_ROLES = (
    "SOC Analyst",
    "Incident Commander",
    "Compliance Reviewer",
    "SOC Manager",
    "Observer",
)

# Base page permissions (no temporary elevation).
ROLE_PERMISSIONS: dict[str, list[str]] = {
    "Dashboard": ["SOC Analyst", "SOC Manager", "Observer"],
    "Active Operations": ["Incident Commander", "SOC Manager", "Compliance Reviewer"],
    "Compliance Operations": ["Compliance Reviewer", "SOC Manager"],
    "Agent Workflow": list(ALL_ROLES),
    "Logs & Evidence": list(ALL_ROLES),
    "Final Report": [
        "SOC Analyst",
        "Incident Commander",
        "Compliance Reviewer",
        "SOC Manager",
        "Observer",
    ],
    "Compliance": ["Compliance Reviewer", "SOC Manager"],
    "System Metrics": list(ALL_ROLES),
    "SOC Command Center": ["SOC Manager", "Observer"],
    "Access Elevation Requests": ["SOC Manager"],
}

# Unified sidebar — every role sees the full list (locked when not permitted).
UNIFIED_SIDEBAR_NAV: list[str] = [
    "Dashboard",
    "Logs & Evidence",
    "Agent Workflow",
    "Compliance Operations",
    "Compliance",
    "Active Operations",
    "SOC Command Center",
    "Access Elevation Requests",
    "System Metrics",
    "Final Report",
]

# Legacy alias kept for imports; all roles use UNIFIED_SIDEBAR_NAV in the UI.
ROLE_NAV_ITEMS: dict[str, list[str]] = {role: list(UNIFIED_SIDEBAR_NAV) for role in ALL_ROLES}

ELEVATION_APPROVER_ROLE = "SOC Manager"

PAGE_NAV_ICONS: dict[str, str] = {
    "Dashboard": "📊",
    "SOC Command Center": "📡",
    "Active Operations": "🎯",
    "Agent Workflow": "🔄",
    "Logs & Evidence": "📋",
    "Compliance Operations": "📑",
    "Compliance": "🛡️",
    "Final Report": "📄",
    "System Metrics": "📊",
    "Access Elevation Requests": "🔐",
}

ELEVATION_DURATIONS = (15, 30, 60)

# Keys cleared on logout — elevation state intentionally excluded.
LOGOUT_PRESERVED_KEYS = (
    "access_requests",
    "temporary_grants",
    "platform_audit",
    "_access_request_seq",
)


def init_access_state() -> None:
    """Initialize elevation / audit session keys (persist across role logout)."""
    if "access_requests" not in st.session_state:
        st.session_state.access_requests = []
    if "temporary_grants" not in st.session_state:
        st.session_state.temporary_grants = []
    if "platform_audit" not in st.session_state:
        st.session_state.platform_audit = []
    if "_access_request_seq" not in st.session_state:
        st.session_state._access_request_seq = 0


def _next_request_id() -> str:
    st.session_state._access_request_seq = int(st.session_state.get("_access_request_seq", 0)) + 1
    return f"REQ-2026-{st.session_state._access_request_seq:04d}"


def _now() -> datetime:
    return datetime.now()


def _parse_dt(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value)
        except ValueError:
            return None
    return None


def base_can_access_page(role: str, page: str) -> bool:
    """Role permission without temporary elevation."""
    allowed = ROLE_PERMISSIONS.get(page)
    if allowed is None:
        return True
    return role in allowed


def cleanup_expired_grants() -> list[dict]:
    """Remove expired grants; append audit entries; return removed grants."""
    init_access_state()
    now = _now()
    grants: list[dict] = list(st.session_state.temporary_grants)
    active: list[dict] = []
    expired: list[dict] = []
    for grant in grants:
        expires = _parse_dt(grant.get("expires_at"))
        if expires and expires <= now:
            expired.append(grant)
        else:
            active.append(grant)
    if expired:
        st.session_state.temporary_grants = active
        for grant in expired:
            append_platform_audit(
                event="temporary_access_expired",
                role=grant.get("role", "—"),
                section=grant.get("section", "—"),
                detail=f"Grant {grant.get('request_id', '—')} expired",
                request_id=grant.get("request_id"),
            )
    return expired


def has_temporary_access(role: str, page: str) -> bool:
    """True if an approved, non-expired grant covers this role and page."""
    init_access_state()
    now = _now()
    for grant in st.session_state.temporary_grants:
        if grant.get("role") != role:
            continue
        if grant.get("section") != page:
            continue
        expires = _parse_dt(grant.get("expires_at"))
        if expires and expires > now:
            return True
    return False


def can_access_page_with_elevation(role: str, page: str) -> bool:
    """Base RBAC OR active temporary grant for this page."""
    return base_can_access_page(role, page) or has_temporary_access(role, page)


def allowed_roles_label(page: str) -> str:
    return ", ".join(ROLE_PERMISSIONS.get(page, ALL_ROLES))


def nav_items_for_role(role: str) -> list[str]:
    """Full navigation list for every role (visibility; access enforced separately)."""
    return list(UNIFIED_SIDEBAR_NAV)


def nav_lock_title(role: str, page: str) -> str:
    """Tooltip for locked sidebar entries."""
    if base_can_access_page(role, page):
        return ""
    if has_temporary_access(role, page):
        return ""
    if page == "Access Elevation Requests":
        return "SOC Manager approval required"
    return "Temporary access required"


def is_nav_entry_locked(role: str, page: str) -> bool:
    """True when the role cannot open the page without elevation."""
    return not can_access_page_with_elevation(role, page)


def sidebar_nav_for_role(role: str) -> list[tuple[str, str]]:
    """Ordered (page_name, icon) tuples for sidebar radio."""
    return [(name, PAGE_NAV_ICONS.get(name, "◉")) for name in nav_items_for_role(role)]


def get_active_grant(role: str, page: str) -> dict | None:
    init_access_state()
    now = _now()
    for grant in st.session_state.temporary_grants:
        if grant.get("role") == role and grant.get("section") == page:
            expires = _parse_dt(grant.get("expires_at"))
            if expires and expires > now:
                return grant
    return None


def minutes_until_expiry(grant: dict) -> int:
    expires = _parse_dt(grant.get("expires_at"))
    if not expires:
        return 0
    delta = expires - _now()
    if delta.total_seconds() <= 0:
        return 0
    return max(1, int((delta.total_seconds() + 59) // 60))


def sidebar_nav_entry(role: str, page: str) -> dict[str, Any]:
    """Metadata for one sidebar row."""
    grant = get_active_grant(role, page)
    locked = is_nav_entry_locked(role, page)
    return {
        "page": page,
        "icon": PAGE_NAV_ICONS.get(page, "◉"),
        "locked": locked,
        "lock_title": nav_lock_title(role, page) if locked else "",
        "has_grant": grant is not None,
        "grant_minutes": minutes_until_expiry(grant) if grant else 0,
    }


def sidebar_nav_entries(role: str) -> list[dict[str, Any]]:
    """Full sidebar metadata for render (unified list, per-row lock/grant state)."""
    return [sidebar_nav_entry(role, page) for page in nav_items_for_role(role)]


def append_platform_audit(
    *,
    event: str,
    role: str,
    section: str,
    detail: str,
    request_id: str | None = None,
    manager: str | None = None,
    duration_minutes: int | None = None,
) -> None:
    init_access_state()
    now = _now()
    st.session_state.platform_audit.append(
        {
            "event": event,
            "role": role,
            "section": section,
            "detail": detail,
            "request_id": request_id,
            "manager": manager,
            "duration_minutes": duration_minutes,
            "timestamp": now.isoformat(timespec="seconds"),
            "display": now.strftime("%Y-%m-%d %H:%M:%S"),
        }
    )


def submit_access_request(
    requester_role: str,
    section: str,
    reason: str,
    duration_minutes: int,
    incident_id: str | None = None,
) -> dict:
    init_access_state()
    now = _now()
    request_id = _next_request_id()
    row = {
        "request_id": request_id,
        "requester_role": requester_role,
        "requested_section": section,
        "incident_id": incident_id or "",
        "reason": reason.strip(),
        "requested_duration": int(duration_minutes),
        "status": "Pending",
        "created_date": now.strftime("%Y-%m-%d"),
        "created_day": now.strftime("%A"),
        "created_time": now.strftime("%H:%M:%S"),
        "created_at": now.isoformat(timespec="seconds"),
        "expires_at": None,
        "approved_by": None,
        "approved_at": None,
        "denied_at": None,
        "denied_by": None,
    }
    st.session_state.access_requests.append(row)
    append_platform_audit(
        event="access_request_submitted",
        role=requester_role,
        section=section,
        detail=reason.strip()[:200] or "No reason provided",
        request_id=request_id,
        duration_minutes=duration_minutes,
    )
    return row


def _find_request(request_id: str) -> dict | None:
    init_access_state()
    for req in st.session_state.access_requests:
        if req.get("request_id") == request_id:
            return req
    return None


def approve_access_request(request_id: str, manager_role: str = "SOC Manager") -> bool:
    req = _find_request(request_id)
    if not req or req.get("status") != "Pending":
        return False
    now = _now()
    duration = int(req.get("requested_duration", 15))
    expires = now + timedelta(minutes=duration)
    req["status"] = "Approved"
    req["approved_by"] = manager_role
    req["approved_at"] = now.isoformat(timespec="seconds")
    req["expires_at"] = expires.isoformat(timespec="seconds")
    grant = {
        "role": req["requester_role"],
        "section": req["requested_section"],
        "expires_at": expires.isoformat(timespec="seconds"),
        "request_id": request_id,
        "approved_by": manager_role,
    }
    st.session_state.temporary_grants.append(grant)
    append_platform_audit(
        event="access_approved",
        role=req["requester_role"],
        section=req["requested_section"],
        detail=f"Approved by {manager_role} for {duration} minutes",
        request_id=request_id,
        manager=manager_role,
        duration_minutes=duration,
    )
    return True


def deny_access_request(request_id: str, manager_role: str = "SOC Manager") -> bool:
    req = _find_request(request_id)
    if not req or req.get("status") != "Pending":
        return False
    now = _now()
    req["status"] = "Denied"
    req["denied_by"] = manager_role
    req["denied_at"] = now.isoformat(timespec="seconds")
    append_platform_audit(
        event="access_denied",
        role=req["requester_role"],
        section=req["requested_section"],
        detail=f"Denied by {manager_role}",
        request_id=request_id,
        manager=manager_role,
    )
    return True


def recent_platform_audit(limit: int = 12) -> list[dict]:
    init_access_state()
    return list(reversed(st.session_state.platform_audit[-limit:]))
