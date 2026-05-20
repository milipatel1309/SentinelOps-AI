"""Session-scoped RBAC, role navigation, and temporary access elevation (demo only)."""

from __future__ import annotations

from datetime import date, datetime, time, timedelta
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

ELEVATION_DURATIONS = (15, 30, 60)  # legacy; quick-duration buttons replace selectbox

ACCESS_TIMEZONES = ("EST", "PST", "CST", "UTC")
TZ_UTC_OFFSET_HOURS: dict[str, int] = {
    "EST": -5,
    "PST": -8,
    "CST": -6,
    "UTC": 0,
}
MAX_ACCESS_WINDOW_HOURS = 24

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


def _format_display_point(d: date, t: time, tz: str) -> str:
    dt = datetime.combine(d, t)
    stamp = dt.strftime("%b %d, %Y %I:%M %p").replace(" 0", " ").replace("AM", "AM").replace("PM", "PM")
    if stamp.startswith("0"):
        stamp = stamp[1:]
    return f"{stamp} {tz}"


def _duration_display(minutes: int) -> str:
    if minutes < 60:
        return f"{minutes} minute{'s' if minutes != 1 else ''}"
    hours = minutes // 60
    rem = minutes % 60
    if rem == 0:
        return f"{hours} hour{'s' if hours != 1 else ''}"
    return f"{hours} hour{'s' if hours != 1 else ''} {rem} minutes"


def _local_to_utc(d: date, t: time, tz: str) -> datetime:
    local = datetime.combine(d, t)
    return local - timedelta(hours=TZ_UTC_OFFSET_HOURS.get(tz, 0))


def _utc_to_local(d_utc: datetime, tz: str) -> datetime:
    return d_utc + timedelta(hours=TZ_UTC_OFFSET_HOURS.get(tz, 0))


def parse_access_window(
    start_date: date,
    start_time: time,
    start_tz: str,
    end_date: date,
    end_time: time,
    end_tz: str,
) -> tuple[datetime, datetime, str]:
    """Return UTC start/end and a human-readable window preview string."""
    start_utc = _local_to_utc(start_date, start_time, start_tz)
    end_utc = _local_to_utc(end_date, end_time, end_tz)
    minutes = max(0, int((end_utc - start_utc).total_seconds() // 60))
    start_label = _format_display_point(start_date, start_time, start_tz)
    end_label = _format_display_point(end_date, end_time, end_tz)
    preview = (
        f"Requested access window: {start_label} → {end_label} "
        f"({_duration_display(minutes)})"
    )
    return start_utc, end_utc, preview


def validate_access_window(start_utc: datetime, end_utc: datetime) -> str | None:
    if end_utc <= start_utc:
        return "Access end must be after access start."
    hours = (end_utc - start_utc).total_seconds() / 3600
    if hours > MAX_ACCESS_WINDOW_HOURS:
        return "Access window cannot exceed 24 hours."
    return None


def migrate_access_request(req: dict) -> dict:
    """Backfill scheduling fields for legacy duration-only requests."""
    if req.get("access_start_iso") and req.get("access_end_iso"):
        return req
    created = _parse_dt(req.get("created_at")) or _now()
    duration = int(req.get("requested_duration") or req.get("calculated_duration_minutes") or 15)
    end = created + timedelta(minutes=duration)
    req["access_start_iso"] = created.isoformat(timespec="seconds")
    req["access_end_iso"] = end.isoformat(timespec="seconds")
    req["start_timezone"] = req.get("start_timezone") or "UTC"
    req["end_timezone"] = req.get("end_timezone") or req["start_timezone"]
    req["calculated_duration_minutes"] = duration
    req["calculated_duration_display"] = _duration_display(duration)
    req["start_display"] = created.strftime("%b %d, %Y %I:%M %p UTC")
    req["end_display"] = end.strftime("%b %d, %Y %I:%M %p UTC")
    req.setdefault("requested_duration", duration)
    return req


def list_access_requests() -> list[dict]:
    init_access_state()
    return [migrate_access_request(dict(r)) for r in st.session_state.access_requests]


def _grant_starts_at(grant: dict) -> datetime | None:
    return _parse_dt(grant.get("starts_at") or grant.get("access_start"))


def _grant_expires_at(grant: dict) -> datetime | None:
    return _parse_dt(grant.get("expires_at") or grant.get("access_end"))


def _grant_is_active(grant: dict, now: datetime | None = None) -> bool:
    now = now or _now()
    starts = _grant_starts_at(grant)
    expires = _grant_expires_at(grant)
    if starts and now < starts:
        return False
    if expires and expires <= now:
        return False
    return bool(expires and expires > now)


def _grant_is_scheduled(grant: dict, now: datetime | None = None) -> bool:
    now = now or _now()
    starts = _grant_starts_at(grant)
    expires = _grant_expires_at(grant)
    if not starts or not expires:
        return False
    return starts > now and expires > now


def base_can_access_page(role: str, page: str) -> bool:
    """Role permission without temporary elevation."""
    allowed = ROLE_PERMISSIONS.get(page)
    if allowed is None:
        return True
    return role in allowed


def _process_grant_activation_audit() -> None:
    """Log access_activated once when wall clock crosses grant start."""
    init_access_state()
    now = _now()
    for grant in st.session_state.temporary_grants:
        if grant.get("activation_logged"):
            continue
        starts = _grant_starts_at(grant)
        expires = _grant_expires_at(grant)
        if not starts or not expires:
            continue
        if starts <= now < expires:
            grant["activation_logged"] = True
            append_platform_audit(
                event="access_activated",
                role=grant.get("role", "—"),
                section=grant.get("section", "—"),
                detail=(
                    f"Temporary access active for {grant.get('request_id', '—')} "
                    f"until {expires.strftime('%Y-%m-%d %H:%M:%S')}"
                ),
                request_id=grant.get("request_id"),
            )


def cleanup_expired_grants() -> list[dict]:
    """Remove expired grants; append audit entries; return removed grants."""
    init_access_state()
    _process_grant_activation_audit()
    now = _now()
    grants: list[dict] = list(st.session_state.temporary_grants)
    active: list[dict] = []
    expired: list[dict] = []
    for grant in grants:
        expires = _grant_expires_at(grant)
        if expires and expires <= now:
            expired.append(grant)
        else:
            active.append(grant)
    if expired:
        st.session_state.temporary_grants = active
        for grant in expired:
            append_platform_audit(
                event="access_expired",
                role=grant.get("role", "—"),
                section=grant.get("section", "—"),
                detail=f"Access expired — grant {grant.get('request_id', '—')}",
                request_id=grant.get("request_id"),
            )
    return expired


def has_temporary_access(role: str, page: str) -> bool:
    """True if an approved grant is inside its access window (start ≤ now < end)."""
    init_access_state()
    for grant in st.session_state.temporary_grants:
        if grant.get("role") != role:
            continue
        if grant.get("section") != page:
            continue
        if _grant_is_active(grant):
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


def get_grant_for_page(role: str, page: str) -> dict | None:
    """Latest non-expired grant for role/page (scheduled or active)."""
    init_access_state()
    now = _now()
    match: dict | None = None
    for grant in st.session_state.temporary_grants:
        if grant.get("role") != role or grant.get("section") != page:
            continue
        expires = _grant_expires_at(grant)
        if expires and expires <= now:
            continue
        match = grant
    return match


def get_active_grant(role: str, page: str) -> dict | None:
    grant = get_grant_for_page(role, page)
    if grant and _grant_is_active(grant):
        return grant
    return None


def get_scheduled_grant(role: str, page: str) -> dict | None:
    grant = get_grant_for_page(role, page)
    if grant and _grant_is_scheduled(grant):
        return grant
    return None


def minutes_until_expiry(grant: dict) -> int:
    expires = _grant_expires_at(grant)
    if not expires:
        return 0
    delta = expires - _now()
    if delta.total_seconds() <= 0:
        return 0
    return max(1, int((delta.total_seconds() + 59) // 60))


def minutes_until_start(grant: dict) -> int:
    starts = _grant_starts_at(grant)
    if not starts:
        return 0
    delta = starts - _now()
    if delta.total_seconds() <= 0:
        return 0
    return max(1, int((delta.total_seconds() + 59) // 60))


def sidebar_nav_entry(role: str, page: str) -> dict[str, Any]:
    """Metadata for one sidebar row."""
    active = get_active_grant(role, page)
    scheduled = get_scheduled_grant(role, page) if not active else None
    grant = active or scheduled
    locked = is_nav_entry_locked(role, page)
    if scheduled and not active:
        grant_minutes = minutes_until_start(scheduled)
        grant_hint = f"starts in {grant_minutes}m"
    elif active:
        grant_minutes = minutes_until_expiry(active)
        grant_hint = f"{grant_minutes}m left"
    else:
        grant_minutes = 0
        grant_hint = ""
    return {
        "page": page,
        "icon": PAGE_NAV_ICONS.get(page, "◉"),
        "locked": locked,
        "lock_title": nav_lock_title(role, page) if locked else "",
        "has_grant": grant is not None,
        "grant_scheduled": scheduled is not None,
        "grant_minutes": grant_minutes,
        "grant_hint": grant_hint,
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


def _window_key(prefix: str, field: str) -> str:
    return f"{prefix}_{field}"


def _default_end_from_start(
    start_date: date,
    start_time: time,
    start_tz: str,
    *,
    minutes: int = 30,
) -> tuple[date, time]:
    start_local = datetime.combine(start_date, start_time)
    end_local = start_local + timedelta(minutes=minutes)
    return end_local.date(), end_local.time()


def render_access_request_form(
    section: str,
    *,
    key_prefix: str | None = None,
) -> dict[str, Any] | None:
    """
    Enterprise scheduling UI for temporary access.
    Returns window payload dict on valid submit intent, else None.
    """
    prefix = key_prefix or f"elev_{section}"
    now = _now()
    today = now.date()
    now_time = now.time().replace(second=0, microsecond=0)

    st.caption("SOC Manager will review the requested access window and approve or deny.")

    c1, c2, c3 = st.columns([1, 1, 1])
    with c1:
        start_date = st.date_input("Access Start — date", value=today, key=_window_key(prefix, "start_date"))
    with c2:
        start_time = st.time_input(
            "Access Start — time",
            value=now_time,
            key=_window_key(prefix, "start_time"),
        )
    with c3:
        start_tz = st.selectbox(
            "Access Start — timezone",
            ACCESS_TIMEZONES,
            index=0,
            key=_window_key(prefix, "start_tz"),
        )

    end_default_date, end_default_time = _default_end_from_start(start_date, start_time, start_tz, minutes=30)
    end_date_key = _window_key(prefix, "end_date")
    end_time_key = _window_key(prefix, "end_time")
    end_tz_key = _window_key(prefix, "end_tz")
    if end_date_key not in st.session_state:
        st.session_state[end_date_key] = end_default_date
    if end_time_key not in st.session_state:
        st.session_state[end_time_key] = end_default_time
    if end_tz_key not in st.session_state:
        st.session_state[end_tz_key] = start_tz

    qb1, qb2, qb3, qb4 = st.columns(4)
    with qb1:
        if st.button("15 minutes", key=_window_key(prefix, "q15")):
            ed, et = _default_end_from_start(start_date, start_time, start_tz, minutes=15)
            st.session_state[end_date_key] = ed
            st.session_state[end_time_key] = et
            st.session_state[end_tz_key] = start_tz
            st.rerun()
    with qb2:
        if st.button("30 minutes", key=_window_key(prefix, "q30")):
            ed, et = _default_end_from_start(start_date, start_time, start_tz, minutes=30)
            st.session_state[end_date_key] = ed
            st.session_state[end_time_key] = et
            st.session_state[end_tz_key] = start_tz
            st.rerun()
    with qb3:
        if st.button("1 hour", key=_window_key(prefix, "q60")):
            ed, et = _default_end_from_start(start_date, start_time, start_tz, minutes=60)
            st.session_state[end_date_key] = ed
            st.session_state[end_time_key] = et
            st.session_state[end_tz_key] = start_tz
            st.rerun()
    with qb4:
        if st.button("Same business day", key=_window_key(prefix, "q_eod")):
            st.session_state[end_date_key] = start_date
            st.session_state[end_time_key] = time(17, 0)
            st.session_state[end_tz_key] = start_tz
            st.rerun()

    e1, e2, e3 = st.columns([1, 1, 1])
    with e1:
        end_date = st.date_input("Access End — date", key=end_date_key)
    with e2:
        end_time = st.time_input("Access End — time", key=end_time_key)
    with e3:
        end_tz = st.selectbox("Access End — timezone", ACCESS_TIMEZONES, key=end_tz_key)

    start_utc, end_utc, preview = parse_access_window(
        start_date, start_time, start_tz, end_date, end_time, end_tz
    )
    duration_minutes = max(0, int((end_utc - start_utc).total_seconds() // 60))
    st.markdown(f'<p style="color:#8eb9d0;font-size:0.88rem;">{preview}</p>', unsafe_allow_html=True)

    validation_error = validate_access_window(start_utc, end_utc)
    if validation_error:
        st.error(validation_error)

    return {
        "start_date": start_date,
        "start_time": start_time,
        "start_tz": start_tz,
        "end_date": end_date,
        "end_time": end_time,
        "end_tz": end_tz,
        "start_utc": start_utc,
        "end_utc": end_utc,
        "preview": preview,
        "duration_minutes": duration_minutes,
        "duration_display": _duration_display(duration_minutes),
        "start_display": _format_display_point(start_date, start_time, start_tz),
        "end_display": _format_display_point(end_date, end_time, end_tz),
        "validation_error": validation_error,
    }


def submit_access_request(
    requester_role: str,
    section: str,
    reason: str,
    *,
    window: dict[str, Any],
    incident_id: str | None = None,
) -> dict:
    init_access_state()
    now = _now()
    request_id = _next_request_id()
    duration_minutes = int(window["duration_minutes"])
    row = {
        "request_id": request_id,
        "requester_role": requester_role,
        "requested_section": section,
        "incident_id": incident_id or "",
        "reason": reason.strip(),
        "requested_duration": duration_minutes,
        "access_start_iso": window["start_utc"].isoformat(timespec="seconds"),
        "access_end_iso": window["end_utc"].isoformat(timespec="seconds"),
        "start_display": window["start_display"],
        "end_display": window["end_display"],
        "start_timezone": window["start_tz"],
        "end_timezone": window["end_tz"],
        "start_date": str(window["start_date"]),
        "start_time": window["start_time"].strftime("%H:%M:%S"),
        "end_date": str(window["end_date"]),
        "end_time": window["end_time"].strftime("%H:%M:%S"),
        "calculated_duration_minutes": duration_minutes,
        "calculated_duration_display": window["duration_display"],
        "window_preview": window["preview"],
        "status": "Pending",
        "created_date": now.strftime("%Y-%m-%d"),
        "created_day": now.strftime("%A"),
        "created_time": now.strftime("%H:%M:%S"),
        "created_timestamp": now.strftime("%Y-%m-%d %H:%M:%S"),
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
        detail=window["preview"],
        request_id=request_id,
        duration_minutes=duration_minutes,
    )
    return row


def _find_request(request_id: str) -> dict | None:
    init_access_state()
    for req in st.session_state.access_requests:
        if req.get("request_id") == request_id:
            return migrate_access_request(req)
    return None


def approve_access_request(request_id: str, manager_role: str = "SOC Manager") -> bool:
    req = _find_request(request_id)
    if not req or req.get("status") != "Pending":
        return False
    now = _now()
    starts = _parse_dt(req.get("access_start_iso")) or now
    expires = _parse_dt(req.get("access_end_iso")) or (starts + timedelta(minutes=15))
    duration = int(req.get("calculated_duration_minutes") or req.get("requested_duration", 15))
    req["status"] = "Approved"
    req["approved_by"] = manager_role
    req["approved_at"] = now.isoformat(timespec="seconds")
    req["expires_at"] = expires.isoformat(timespec="seconds")
    grant = {
        "role": req["requester_role"],
        "section": req["requested_section"],
        "starts_at": starts.isoformat(timespec="seconds"),
        "expires_at": expires.isoformat(timespec="seconds"),
        "access_start": starts.isoformat(timespec="seconds"),
        "access_end": expires.isoformat(timespec="seconds"),
        "request_id": request_id,
        "approved_by": manager_role,
        "activation_logged": False,
    }
    st.session_state.temporary_grants.append(grant)
    window_detail = (
        f"{req.get('start_display', starts.isoformat())} → "
        f"{req.get('end_display', expires.isoformat())} "
        f"({req.get('calculated_duration_display', _duration_display(duration))})"
    )
    append_platform_audit(
        event="access_approved",
        role=req["requester_role"],
        section=req["requested_section"],
        detail=f"Approved by {manager_role}: {window_detail}",
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
