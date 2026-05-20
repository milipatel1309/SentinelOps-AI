"""Demo user profiles stored in Streamlit session state (no real auth)."""

from __future__ import annotations

from datetime import datetime
from typing import Any

import streamlit as st

from utils.access_control import ALL_ROLES, append_platform_audit
from utils.datetime_utils import DEFAULT_TIMEZONE, PROFILE_TIMEZONES, now_utc, utc_iso

SEED_USERS: list[dict[str, Any]] = [
    {
        "user_id": "USR-001",
        "full_name": "Jordan Lee",
        "username": "jordan.analyst",
        "password": "analyst123",
        "role": "SOC Analyst",
        "department": "SOC Operations",
        "created_at_utc": "2026-05-01T12:00:00+00:00",
        "timezone": "America/New_York",
    },
    {
        "user_id": "USR-002",
        "full_name": "Sam Rivera",
        "username": "sam.manager",
        "password": "manager123",
        "role": "SOC Manager",
        "department": "Security Operations",
        "created_at_utc": "2026-05-01T12:00:00+00:00",
        "timezone": "America/New_York",
    },
    {
        "user_id": "USR-003",
        "full_name": "Morgan Blake",
        "username": "morgan.compliance",
        "password": "compliance123",
        "role": "Compliance Reviewer",
        "department": "Governance & Risk",
        "created_at_utc": "2026-05-01T12:00:00+00:00",
        "timezone": "America/New_York",
    },
    {
        "user_id": "USR-004",
        "full_name": "Alex Chen",
        "username": "alex.commander",
        "password": "commander123",
        "role": "Incident Commander",
        "department": "Incident Response",
        "created_at_utc": "2026-05-01T12:00:00+00:00",
        "timezone": "America/New_York",
    },
    {
        "user_id": "USR-005",
        "full_name": "Taylor Brooks",
        "username": "taylor.observer",
        "password": "observer123",
        "role": "Observer",
        "department": "Security Operations",
        "created_at_utc": "2026-05-01T12:00:00+00:00",
        "timezone": "America/New_York",
    },
]


def seed_demo_users() -> list[dict[str, Any]]:
    """Return a copy of the built-in demo user seed list."""
    return [dict(u) for u in SEED_USERS]


def _demo_accounts_html() -> str:
    rows = "".join(
        f"<tr><td>{u['role']}</td>"
        f"<td><code>{u['username']}</code></td>"
        f"<td><code>{u['password']}</code></td></tr>"
        for u in SEED_USERS
    )
    return (
        '<div class="demo-accounts-card">'
        '<div class="demo-accounts-title">Demo accounts</div>'
        '<table class="demo-accounts-table">'
        "<thead><tr><th>Role</th><th>Username</th><th>Password</th></tr></thead>"
        f"<tbody>{rows}</tbody></table></div>"
    )


DEMO_ACCOUNTS_HTML = _demo_accounts_html()


def _next_user_id() -> str:
    users = st.session_state.get("demo_users") or []
    max_num = 0
    for u in users:
        uid = u.get("user_id", "")
        if uid.startswith("USR-") and uid[4:].isdigit():
            max_num = max(max_num, int(uid[4:]))
    return f"USR-{max_num + 1:03d}"


def init_user_state() -> None:
    if "demo_users" not in st.session_state:
        st.session_state.demo_users = [dict(u) for u in SEED_USERS]
    if "current_user" not in st.session_state:
        st.session_state.current_user = None
    _migrate_demo_role()


def _migrate_demo_role() -> None:
    """Map legacy demo_role to current_user.role when upgrading mid-session."""
    if st.session_state.get("current_user"):
        return
    legacy_role = st.session_state.get("demo_role")
    if not legacy_role or not st.session_state.get("authenticated"):
        return
    match = next(
        (u for u in st.session_state.demo_users if u.get("role") == legacy_role),
        None,
    )
    if match:
        st.session_state.current_user = dict(match)
    else:
        st.session_state.current_user = {
            "user_id": "USR-LEGACY",
            "full_name": legacy_role,
            "username": legacy_role.lower().replace(" ", "."),
            "password": "",
            "role": legacy_role,
            "department": "",
            "created_at_utc": utc_iso(now_utc()),
            "timezone": DEFAULT_TIMEZONE,
        }


def get_current_user() -> dict[str, Any] | None:
    init_user_state()
    user = st.session_state.get("current_user")
    return dict(user) if user else None


def get_current_user_id() -> str | None:
    user = get_current_user()
    return user.get("user_id") if user else None


def get_current_role() -> str:
    user = get_current_user()
    if user and user.get("role"):
        return user["role"]
    legacy = st.session_state.get("demo_role")
    if legacy:
        return legacy
    return "SOC Analyst"


def get_user_timezone() -> str:
    user = get_current_user()
    if user and user.get("timezone"):
        return user["timezone"]
    return DEFAULT_TIMEZONE


def find_user_by_credentials(username: str, password: str) -> dict[str, Any] | None:
    init_user_state()
    uname = username.strip().lower()
    for u in st.session_state.demo_users:
        if u.get("username", "").lower() == uname and u.get("password") == password:
            return dict(u)
    return None


def create_profile(
    *,
    full_name: str,
    username: str,
    password: str,
    role: str,
    department: str = "",
    timezone: str = DEFAULT_TIMEZONE,
) -> dict[str, Any]:
    init_user_state()
    uname = username.strip().lower()
    if any(u.get("username", "").lower() == uname for u in st.session_state.demo_users):
        raise ValueError("Username already exists.")
    if role not in ALL_ROLES:
        raise ValueError("Invalid role.")
    if timezone not in PROFILE_TIMEZONES:
        timezone = DEFAULT_TIMEZONE
    user = {
        "user_id": _next_user_id(),
        "full_name": full_name.strip(),
        "username": uname,
        "password": password,
        "role": role,
        "department": department.strip(),
        "created_at_utc": utc_iso(now_utc()),
        "timezone": timezone,
    }
    st.session_state.demo_users.append(user)
    append_platform_audit(
        event="profile_created",
        actor_username=user["username"],
        actor_role=user["role"],
        target_user=user["username"],
        section="Authentication",
        detail=f"Profile created for {user['full_name']} ({user['role']})",
        viewer_timezone=timezone,
    )
    return user


def login_user(username: str, password: str) -> dict[str, Any] | None:
    user = find_user_by_credentials(username, password)
    if not user:
        return None
    st.session_state.current_user = user
    st.session_state.authenticated = True
    st.session_state.demo_role = user["role"]
    append_platform_audit(
        event="logged_in",
        actor_username=user["username"],
        actor_role=user["role"],
        target_user=user["username"],
        section="Authentication",
        detail=f"{user['full_name']} signed in",
        viewer_timezone=user.get("timezone", DEFAULT_TIMEZONE),
    )
    return user


def logout_user() -> None:
    """Clear session user; preserve demo_users and elevation state."""
    st.session_state.current_user = None
    st.session_state.authenticated = False
    st.session_state.demo_role = None
    st.session_state.role_landing_applied = False
    st.session_state.demo_incident_preloaded = False
