"""Session-scoped RBAC, role navigation, and temporary access elevation (demo only)."""

from __future__ import annotations

from datetime import date, datetime, time, timedelta
from typing import Any
from zoneinfo import ZoneInfo

import streamlit as st

from utils.datetime_utils import (
    DEFAULT_TIMEZONE,
    PROFILE_TIMEZONES,
    format_display_timestamp,
    format_window_preview,
    local_window_to_utc,
    now_utc,
    parse_utc,
    utc_iso,
    default_end_from_start,
)

ALL_ROLES = (
    "SOC Analyst",
    "Incident Commander",
    "Compliance Reviewer",
    "SOC Manager",
    "Observer",
)

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

MAX_ACCESS_WINDOW_HOURS = 24

LOGOUT_PRESERVED_KEYS = (
    "access_requests",
    "temporary_permissions",
    "temporary_grants",
    "platform_audit",
    "demo_users",
    "_access_request_seq",
    "_permission_seq",
)


def init_access_state() -> None:
    """Initialize elevation / audit session keys (persist across logout)."""
    if "access_requests" not in st.session_state:
        st.session_state.access_requests = []
    if "temporary_permissions" not in st.session_state:
        grants = st.session_state.pop("temporary_grants", None)
        st.session_state.temporary_permissions = list(grants or [])
    if "platform_audit" not in st.session_state:
        st.session_state.platform_audit = []
    if "_access_request_seq" not in st.session_state:
        st.session_state._access_request_seq = 0
    if "_permission_seq" not in st.session_state:
        st.session_state._permission_seq = 0


def _next_request_id() -> str:
    st.session_state._access_request_seq = int(st.session_state.get("_access_request_seq", 0)) + 1
    return f"REQ-2026-{st.session_state._access_request_seq:04d}"


def _next_permission_id() -> str:
    st.session_state._permission_seq = int(st.session_state.get("_permission_seq", 0)) + 1
    return f"PERM-2026-{st.session_state._permission_seq:04d}"


def _parse_dt(value: Any) -> datetime | None:
    return parse_utc(value)


def _duration_display(minutes: int) -> str:
    if minutes < 60:
        return f"{minutes} minute{'s' if minutes != 1 else ''}"
    hours = minutes // 60
    rem = minutes % 60
    if rem == 0:
        return f"{hours} hour{'s' if hours != 1 else ''}"
    return f"{hours} hour{'s' if hours != 1 else ''} {rem} minutes"


def parse_access_window(
    start_date: date,
    start_time: time,
    start_tz: str,
    end_date: date,
    end_time: time,
    end_tz: str,
    *,
    viewer_tz: str | None = None,
) -> tuple[datetime, datetime, str]:
    """Return UTC start/end and a human-readable window preview string."""
    start_utc, end_utc = local_window_to_utc(
        start_date, start_time, start_tz, end_date, end_time, end_tz
    )
    preview = format_window_preview(start_utc, end_utc, viewer_tz or start_tz)
    return start_utc, end_utc, preview


def validate_access_window(start_utc: datetime, end_utc: datetime) -> str | None:
    if end_utc <= start_utc:
        return "Access end must be after access start."
    hours = (end_utc - start_utc).total_seconds() / 3600
    if hours > MAX_ACCESS_WINDOW_HOURS:
        return "Access window cannot exceed 24 hours."
    return None


def migrate_access_request(req: dict) -> dict:
    """Backfill user and scheduling fields for legacy requests."""
    if not req.get("requester_user_id"):
        legacy_role = req.get("requester_role", "SOC Analyst")
        req["requester_user_id"] = f"LEGACY-{legacy_role.replace(' ', '-')}"
        req.setdefault("requester_username", legacy_role.lower().replace(" ", "."))
        req.setdefault("requester_full_name", legacy_role)
        req.setdefault("requester_role", legacy_role)

    if req.get("access_start_utc") and req.get("access_end_utc"):
        req.setdefault("timezone", req.get("timezone") or req.get("start_timezone") or "UTC")
        return req

    if req.get("access_start_iso") and req.get("access_end_iso"):
        req["access_start_utc"] = req["access_start_iso"]
        req["access_end_utc"] = req["access_end_iso"]
        req.setdefault("timezone", req.get("start_timezone") or "UTC")
        return req

    created = _parse_dt(req.get("created_at_utc") or req.get("created_at")) or now_utc()
    duration = int(req.get("requested_duration") or req.get("calculated_duration_minutes") or 15)
    end = created + timedelta(minutes=duration)
    req["access_start_utc"] = utc_iso(created)
    req["access_end_utc"] = utc_iso(end)
    req["timezone"] = req.get("timezone") or req.get("start_timezone") or "UTC"
    req["calculated_duration_minutes"] = duration
    req["calculated_duration_display"] = _duration_display(duration)
    tz = req["timezone"]
    req["start_display"] = format_display_timestamp(created, tz)
    req["end_display"] = format_display_timestamp(end, tz)
    req.setdefault("requested_duration", duration)
    return req


def migrate_permission(grant: dict) -> dict:
    """Normalize legacy role-based grants to user-scoped permissions."""
    if grant.get("permission_id"):
        grant.setdefault("access_start_utc", grant.get("starts_at") or grant.get("access_start"))
        grant.setdefault("access_end_utc", grant.get("expires_at") or grant.get("access_end"))
        return grant
    role = grant.get("role", "LEGACY")
    grant["permission_id"] = grant.get("request_id") or _next_permission_id()
    grant["user_id"] = grant.get("user_id") or f"LEGACY-{role.replace(' ', '-')}"
    grant.setdefault("username", role.lower().replace(" ", "."))
    grant["section"] = grant.get("section", "")
    grant["access_start_utc"] = grant.get("starts_at") or grant.get("access_start")
    grant["access_end_utc"] = grant.get("expires_at") or grant.get("access_end")
    grant.setdefault("approved_by", grant.get("approved_by", "SOC Manager"))
    grant.setdefault("status", "active")
    return grant


def list_access_requests() -> list[dict]:
    init_access_state()
    return [migrate_access_request(dict(r)) for r in st.session_state.access_requests]


def list_temporary_permissions() -> list[dict]:
    init_access_state()
    return [migrate_permission(dict(g)) for g in st.session_state.temporary_permissions]


def _permission_starts_at(grant: dict) -> datetime | None:
    return _parse_dt(
        grant.get("access_start_utc")
        or grant.get("starts_at")
        or grant.get("access_start")
    )


def _permission_expires_at(grant: dict) -> datetime | None:
    return _parse_dt(
        grant.get("access_end_utc")
        or grant.get("expires_at")
        or grant.get("access_end")
    )


def _permission_is_active(grant: dict, now: datetime | None = None) -> bool:
    now = now or now_utc()
    starts = _permission_starts_at(grant)
    expires = _permission_expires_at(grant)
    if starts and now < starts:
        return False
    if expires and expires <= now:
        return False
    return bool(expires and expires > now)


def _permission_is_scheduled(grant: dict, now: datetime | None = None) -> bool:
    now = now or now_utc()
    starts = _permission_starts_at(grant)
    expires = _permission_expires_at(grant)
    if not starts or not expires:
        return False
    return starts > now and expires > now


def base_can_access_page(role: str, page: str) -> bool:
    allowed = ROLE_PERMISSIONS.get(page)
    if allowed is None:
        return True
    return role in allowed


def _process_grant_activation_audit() -> None:
    init_access_state()
    now = now_utc()
    for grant in list_temporary_permissions():
        if grant.get("activation_logged"):
            continue
        starts = _permission_starts_at(grant)
        expires = _permission_expires_at(grant)
        if not starts or not expires:
            continue
        if starts <= now < expires:
            grant["activation_logged"] = True
            append_platform_audit(
                event="access_activated",
                actor_username=grant.get("username", "—"),
                actor_role="—",
                target_user=grant.get("username", "—"),
                section=grant.get("section", "—"),
                detail=(
                    f"Temporary access active for {grant.get('permission_id', '—')} "
                    f"until {format_display_timestamp(expires, DEFAULT_TIMEZONE)}"
                ),
                request_id=grant.get("request_id"),
            )


def cleanup_expired_grants() -> list[dict]:
    init_access_state()
    _process_grant_activation_audit()
    now = now_utc()
    grants = list_temporary_permissions()
    active: list[dict] = []
    expired: list[dict] = []
    for grant in grants:
        expires = _permission_expires_at(grant)
        if expires and expires <= now:
            expired.append(grant)
        else:
            active.append(grant)
    if expired:
        st.session_state.temporary_permissions = active
        for grant in expired:
            append_platform_audit(
                event="access_expired",
                actor_username=grant.get("username", "—"),
                actor_role="—",
                target_user=grant.get("username", "—"),
                section=grant.get("section", "—"),
                detail=f"Access expired — {grant.get('permission_id', '—')}",
                request_id=grant.get("request_id"),
            )
    return expired


def has_temporary_access(user_id: str | None, section: str) -> bool:
    """True if an approved grant for this user is inside its access window."""
    if not user_id:
        return False
    init_access_state()
    for grant in list_temporary_permissions():
        if grant.get("user_id") != user_id:
            continue
        if grant.get("section") != section:
            continue
        if _permission_is_active(grant):
            return True
    return False


def can_access_page_with_elevation(role: str, page: str, user_id: str | None = None) -> bool:
    return base_can_access_page(role, page) or has_temporary_access(user_id, page)


def allowed_roles_label(page: str) -> str:
    return ", ".join(ROLE_PERMISSIONS.get(page, ALL_ROLES))


def nav_items_for_role(role: str) -> list[str]:
    return list(UNIFIED_SIDEBAR_NAV)


def nav_lock_title(role: str, page: str, user_id: str | None = None) -> str:
    if base_can_access_page(role, page):
        return ""
    if has_temporary_access(user_id, page):
        return ""
    if page == "Access Elevation Requests":
        return "SOC Manager approval required"
    return "Temporary access required"


def is_nav_entry_locked(role: str, page: str, user_id: str | None = None) -> bool:
    return not can_access_page_with_elevation(role, page, user_id)


def sidebar_nav_for_role(role: str) -> list[tuple[str, str]]:
    return [(name, PAGE_NAV_ICONS.get(name, "◉")) for name in nav_items_for_role(role)]


def get_grant_for_page(user_id: str | None, page: str) -> dict | None:
    init_access_state()
    now = now_utc()
    match: dict | None = None
    for grant in list_temporary_permissions():
        if grant.get("user_id") != user_id or grant.get("section") != page:
            continue
        expires = _permission_expires_at(grant)
        if expires and expires <= now:
            continue
        match = grant
    return match


def get_active_grant(user_id: str | None, page: str) -> dict | None:
    grant = get_grant_for_page(user_id, page)
    if grant and _permission_is_active(grant):
        return grant
    return None


def get_scheduled_grant(user_id: str | None, page: str) -> dict | None:
    grant = get_grant_for_page(user_id, page)
    if grant and _permission_is_scheduled(grant):
        return grant
    return None


def minutes_until_expiry(grant: dict) -> int:
    expires = _permission_expires_at(grant)
    if not expires:
        return 0
    delta = expires - now_utc()
    if delta.total_seconds() <= 0:
        return 0
    return max(1, int((delta.total_seconds() + 59) // 60))


def minutes_until_start(grant: dict) -> int:
    starts = _permission_starts_at(grant)
    if not starts:
        return 0
    delta = starts - now_utc()
    if delta.total_seconds() <= 0:
        return 0
    return max(1, int((delta.total_seconds() + 59) // 60))


def sidebar_nav_entry(role: str, page: str, user_id: str | None = None) -> dict[str, Any]:
    active = get_active_grant(user_id, page)
    scheduled = get_scheduled_grant(user_id, page) if not active else None
    grant = active or scheduled
    locked = is_nav_entry_locked(role, page, user_id)
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
        "lock_title": nav_lock_title(role, page, user_id) if locked else "",
        "has_grant": grant is not None,
        "grant_scheduled": scheduled is not None,
        "grant_minutes": grant_minutes,
        "grant_hint": grant_hint,
    }


def sidebar_nav_entries(role: str, user_id: str | None = None) -> list[dict[str, Any]]:
    return [sidebar_nav_entry(role, page, user_id) for page in nav_items_for_role(role)]


def append_platform_audit(
    *,
    event: str,
    section: str,
    detail: str,
    actor_username: str = "—",
    actor_role: str = "—",
    target_user: str | None = None,
    request_id: str | None = None,
    manager: str | None = None,
    duration_minutes: int | None = None,
    viewer_timezone: str = DEFAULT_TIMEZONE,
    # legacy kwargs
    role: str | None = None,
) -> None:
    init_access_state()
    now = now_utc()
    if role and actor_role == "—":
        actor_role = role
    st.session_state.platform_audit.append(
        {
            "event": event,
            "actor_username": actor_username,
            "actor_role": actor_role,
            "target_user": target_user or actor_username,
            "role": actor_role,
            "section": section,
            "detail": detail,
            "request_id": request_id,
            "manager": manager,
            "duration_minutes": duration_minutes,
            "timestamp_utc": utc_iso(now),
            "display": format_display_timestamp(now, viewer_timezone),
            "timestamp": utc_iso(now),
        }
    )


def _window_key(prefix: str, field: str) -> str:
    return f"{prefix}_{field}"


def render_access_request_form(
    section: str,
    *,
    key_prefix: str | None = None,
    default_timezone: str = DEFAULT_TIMEZONE,
) -> dict[str, Any] | None:
    prefix = key_prefix or f"elev_{section}"
    now = now_utc()
    local_now = now.astimezone(ZoneInfo(default_timezone))
    today = local_now.date()
    now_time = local_now.time().replace(second=0, microsecond=0)
    tz_options = list(PROFILE_TIMEZONES)
    tz_index = tz_options.index(default_timezone) if default_timezone in tz_options else 0

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
            tz_options,
            index=tz_index,
            key=_window_key(prefix, "start_tz"),
        )

    end_default_date, end_default_time = default_end_from_start(
        start_date, start_time, start_tz, minutes=30
    )
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
            ed, et = default_end_from_start(start_date, start_time, start_tz, minutes=15)
            st.session_state[end_date_key] = ed
            st.session_state[end_time_key] = et
            st.session_state[end_tz_key] = start_tz
            st.rerun()
    with qb2:
        if st.button("30 minutes", key=_window_key(prefix, "q30")):
            ed, et = default_end_from_start(start_date, start_time, start_tz, minutes=30)
            st.session_state[end_date_key] = ed
            st.session_state[end_time_key] = et
            st.session_state[end_tz_key] = start_tz
            st.rerun()
    with qb3:
        if st.button("1 hour", key=_window_key(prefix, "q60")):
            ed, et = default_end_from_start(start_date, start_time, start_tz, minutes=60)
            st.session_state[end_date_key] = ed
            st.session_state[end_time_key] = et
            st.session_state[end_tz_key] = start_tz
            st.rerun()
    with qb4:
        if st.button("Today only", key=_window_key(prefix, "q_eod")):
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
        end_tz = st.selectbox("Access End — timezone", tz_options, key=end_tz_key)

    start_utc, end_utc, preview = parse_access_window(
        start_date,
        start_time,
        start_tz,
        end_date,
        end_time,
        end_tz,
        viewer_tz=default_timezone,
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
        "start_display": format_display_timestamp(start_utc, default_timezone),
        "end_display": format_display_timestamp(end_utc, default_timezone),
        "validation_error": validation_error,
    }


def submit_access_request(
    requester: dict[str, Any],
    section: str,
    reason: str,
    *,
    window: dict[str, Any],
    incident_id: str | None = None,
) -> dict:
    init_access_state()
    now = now_utc()
    request_id = _next_request_id()
    duration_minutes = int(window["duration_minutes"])
    tz = requester.get("timezone", window.get("start_tz", DEFAULT_TIMEZONE))
    row = {
        "request_id": request_id,
        "requester_user_id": requester["user_id"],
        "requester_username": requester.get("username", ""),
        "requester_full_name": requester.get("full_name", ""),
        "requester_role": requester.get("role", ""),
        "requested_section": section,
        "incident_id": incident_id or "",
        "reason": reason.strip(),
        "requested_duration": duration_minutes,
        "access_start_utc": utc_iso(window["start_utc"]),
        "access_end_utc": utc_iso(window["end_utc"]),
        "timezone": tz,
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
        "created_at_utc": utc_iso(now),
        "approved_by_user_id": None,
        "approved_by_name": None,
        "approved_at_utc": None,
        "expires_at": None,
        "denied_at": None,
        "denied_by": None,
    }
    st.session_state.access_requests.append(row)
    append_platform_audit(
        event="access_submitted",
        actor_username=requester.get("username", "—"),
        actor_role=requester.get("role", "—"),
        target_user=requester.get("username"),
        section=section,
        detail=window["preview"],
        request_id=request_id,
        duration_minutes=duration_minutes,
        viewer_timezone=tz,
    )
    return row


def _find_request(request_id: str) -> dict | None:
    init_access_state()
    for req in st.session_state.access_requests:
        if req.get("request_id") == request_id:
            return migrate_access_request(req)
    return None


def approve_access_request(
    request_id: str,
    approver: dict[str, Any] | None = None,
    manager_role: str = "SOC Manager",
) -> bool:
    req = _find_request(request_id)
    if not req or req.get("status") != "Pending":
        return False
    now = now_utc()
    starts = _parse_dt(req.get("access_start_utc")) or now
    expires = _parse_dt(req.get("access_end_utc")) or (starts + timedelta(minutes=15))
    duration = int(req.get("calculated_duration_minutes") or req.get("requested_duration", 15))
    approver = approver or {}
    approver_name = approver.get("full_name") or manager_role
    approver_id = approver.get("user_id")
    req["status"] = "Approved"
    req["approved_by_user_id"] = approver_id
    req["approved_by_name"] = approver_name
    req["approved_at_utc"] = utc_iso(now)
    req["approved_by"] = approver_name
    req["approved_at"] = utc_iso(now)
    req["expires_at"] = utc_iso(expires)
    grant = {
        "permission_id": _next_permission_id(),
        "user_id": req["requester_user_id"],
        "username": req.get("requester_username", ""),
        "section": req["requested_section"],
        "access_start_utc": utc_iso(starts),
        "access_end_utc": utc_iso(expires),
        "approved_by": approver_name,
        "status": "active",
        "request_id": request_id,
        "starts_at": utc_iso(starts),
        "expires_at": utc_iso(expires),
        "access_start": utc_iso(starts),
        "access_end": utc_iso(expires),
        "activation_logged": False,
    }
    st.session_state.temporary_permissions.append(grant)
    window_detail = (
        f"{req.get('start_display', format_display_timestamp(starts, req.get('timezone', DEFAULT_TIMEZONE)))} → "
        f"{req.get('end_display', format_display_timestamp(expires, req.get('timezone', DEFAULT_TIMEZONE)))} "
        f"({req.get('calculated_duration_display', _duration_display(duration))})"
    )
    append_platform_audit(
        event="access_approved",
        actor_username=approver.get("username", manager_role),
        actor_role=approver.get("role", manager_role),
        target_user=req.get("requester_username"),
        section=req["requested_section"],
        detail=f"Approved by {approver_name}: {window_detail}",
        request_id=request_id,
        manager=approver_name,
        duration_minutes=duration,
        viewer_timezone=approver.get("timezone", DEFAULT_TIMEZONE),
    )
    return True


def deny_access_request(
    request_id: str,
    approver: dict[str, Any] | None = None,
    manager_role: str = "SOC Manager",
) -> bool:
    req = _find_request(request_id)
    if not req or req.get("status") != "Pending":
        return False
    now = now_utc()
    approver = approver or {}
    approver_name = approver.get("full_name") or manager_role
    req["status"] = "Denied"
    req["denied_by"] = approver_name
    req["denied_at"] = utc_iso(now)
    append_platform_audit(
        event="access_denied",
        actor_username=approver.get("username", manager_role),
        actor_role=approver.get("role", manager_role),
        target_user=req.get("requester_username"),
        section=req["requested_section"],
        detail=f"Denied by {approver_name}",
        request_id=request_id,
        manager=approver_name,
        viewer_timezone=approver.get("timezone", DEFAULT_TIMEZONE),
    )
    return True


def recent_platform_audit(limit: int = 12, viewer_timezone: str = DEFAULT_TIMEZONE) -> list[dict]:
    init_access_state()
    rows = []
    for entry in reversed(st.session_state.platform_audit[-limit:]):
        row = dict(entry)
        ts = row.get("timestamp_utc") or row.get("timestamp")
        row["display"] = format_display_timestamp(ts, viewer_timezone)
        rows.append(row)
    return rows
