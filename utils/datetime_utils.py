"""UTC and user-timezone formatting for demo session state."""

from __future__ import annotations

from datetime import date, datetime, time, timedelta, timezone
from zoneinfo import ZoneInfo

PROFILE_TIMEZONES = (
    "America/New_York",
    "America/Chicago",
    "America/Los_Angeles",
    "UTC",
    "Asia/Kolkata",
)

DEFAULT_TIMEZONE = "America/New_York"


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _ensure_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def parse_utc(value: str | datetime | None) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return _ensure_utc(value)
    if isinstance(value, str):
        raw = value.strip()
        if raw.endswith("Z"):
            raw = raw[:-1] + "+00:00"
        try:
            return _ensure_utc(datetime.fromisoformat(raw))
        except ValueError:
            return None
    return None


def to_user_tz(dt_utc: datetime | str | None, tz_name: str) -> datetime | None:
    parsed = parse_utc(dt_utc) if not isinstance(dt_utc, datetime) else _ensure_utc(dt_utc)
    if parsed is None:
        return None
    try:
        return parsed.astimezone(ZoneInfo(tz_name or DEFAULT_TIMEZONE))
    except Exception:
        return parsed.astimezone(ZoneInfo(DEFAULT_TIMEZONE))


def _tz_abbrev(dt_local: datetime, tz_name: str) -> str:
    try:
        return dt_local.strftime("%Z")
    except Exception:
        return tz_name.split("/")[-1]


def format_display_timestamp(
    dt_utc: datetime | str | None,
    tz: str = DEFAULT_TIMEZONE,
) -> str:
    """
    Example: May 20, 2026 · Wednesday · 12:15 PM EDT
    """
    local = to_user_tz(dt_utc, tz)
    if local is None:
        return "—"
    date_part = local.strftime("%B %d, %Y").replace(" 0", " ")
    day_part = local.strftime("%A")
    time_part = local.strftime("%I:%M %p").lstrip("0")
    abbrev = _tz_abbrev(local, tz)
    return f"{date_part} · {day_part} · {time_part} {abbrev}"


def format_short_date(dt_utc: datetime | str | None, tz: str = DEFAULT_TIMEZONE) -> str:
    local = to_user_tz(dt_utc, tz)
    if local is None:
        return "—"
    return local.strftime("%B %d, %Y").replace(" 0", " ")


def format_time_only(dt_utc: datetime | str | None, tz: str = DEFAULT_TIMEZONE) -> str:
    local = to_user_tz(dt_utc, tz)
    if local is None:
        return "—"
    return local.strftime("%I:%M %p").lstrip("0")


def local_window_to_utc(
    start_date: date,
    start_time: time,
    tz_name: str,
    end_date: date,
    end_time: time,
    end_tz_name: str | None = None,
) -> tuple[datetime, datetime]:
    """Convert local date/time in IANA zones to UTC."""
    end_tz = end_tz_name or tz_name
    start_local = datetime.combine(start_date, start_time).replace(
        tzinfo=ZoneInfo(tz_name or DEFAULT_TIMEZONE)
    )
    end_local = datetime.combine(end_date, end_time).replace(
        tzinfo=ZoneInfo(end_tz or DEFAULT_TIMEZONE)
    )
    return start_local.astimezone(timezone.utc), end_local.astimezone(timezone.utc)


def format_window_preview(
    start_utc: datetime,
    end_utc: datetime,
    tz: str,
) -> str:
    start_label = format_display_timestamp(start_utc, tz)
    end_label = format_display_timestamp(end_utc, tz)
    minutes = max(0, int((end_utc - start_utc).total_seconds() // 60))
    if minutes < 60:
        dur = f"{minutes} minute{'s' if minutes != 1 else ''}"
    else:
        hours, rem = divmod(minutes, 60)
        dur = f"{hours} hour{'s' if hours != 1 else ''}"
        if rem:
            dur += f" {rem} minutes"
    return f"Requested access window: {start_label} → {end_label} ({dur})"


def utc_iso(dt: datetime) -> str:
    return _ensure_utc(dt).isoformat(timespec="seconds")


def default_end_from_start(
    start_date: date,
    start_time: time,
    tz_name: str,
    *,
    minutes: int = 30,
) -> tuple[date, time]:
    start_local = datetime.combine(start_date, start_time).replace(
        tzinfo=ZoneInfo(tz_name or DEFAULT_TIMEZONE)
    )
    end_local = start_local + timedelta(minutes=minutes)
    return end_local.date(), end_local.time()
