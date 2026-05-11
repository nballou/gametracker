"""
Email digest and alerting utilities.

Call init() once at startup to configure credentials and data paths.
The daily_errors dict is populated by orchestrator.py when platform
fetches fail; its contents are included in the daily digest and then cleared.
"""

import csv
import logging
import os
import threading
from datetime import datetime, time as dt_time, timedelta

import yagmail

logger = logging.getLogger("gametracker.digest")

# Populated by orchestrator.py when platform fetches raise exceptions.
# Keys are platform names; values are lists of error message strings.
daily_errors: dict[str, list[str]] = {}

# Set by init()
_data_dir      = "data"
_email_user    = None
_email_password = None


def init(data_dir: str, email_user: str | None, email_password: str | None):
    """Configure digest module. Must be called before any send functions."""
    global _data_dir, _email_user, _email_password
    _data_dir       = data_dir
    _email_user     = email_user
    _email_password = email_password


def send_email(subject: str, body: str):
    """Send a plain-text email to the configured address."""
    logger.info("Sending email: %s", subject)
    try:
        with yagmail.SMTP(_email_user, password=_email_password) as smtp:
            smtp.send(to=_email_user, subject=subject, contents=body)
    except Exception as e:
        logger.error("Email failed: %s", e)


def send_daily_digest(enabled_platforms: list[str]):
    """
    Summarise the past 24 h of telemetry across the enabled platforms and
    email the results, including any errors accumulated in daily_errors.
    Clears daily_errors after sending.
    """
    cutoff       = datetime.utcnow() - timedelta(days=1)
    unique_users = {p: set() for p in enabled_platforms}
    updates      = {p: 0     for p in enabled_platforms}

    for fname in os.listdir(_data_dir):
        if not fname.endswith(".csv"):
            continue
        platform = fname.split("-", 1)[0]
        if platform not in enabled_platforms:
            continue
        with open(os.path.join(_data_dir, fname)) as f:
            for row in csv.DictReader(f):
                try:
                    ts = datetime.fromisoformat(row.get("time", ""))
                except Exception:
                    continue
                if ts >= cutoff:
                    if user := row.get("userName"):
                        unique_users[platform].add(user)
                    updates[platform] += 1

    lines = [f"Daily Telemetry Digest ({datetime.utcnow().date()} UTC)\n"]
    for p in enabled_platforms:
        lines.append(f"{p}: {len(unique_users[p])} unique users, {updates[p]} updates")
    lines.append("")

    for p in enabled_platforms:
        if errs := daily_errors.get(p, []):
            lines.append(f"{p} errors:")
            lines.extend(f"  - {e}" for e in errs)
            lines.append("")
            daily_errors[p].clear()

    send_email("Daily Telemetry Digest", "\n".join(lines))


def schedule_digest(first_time: str = "09:00", enabled_platforms: list[str] = None):
    """
    Schedule the first digest at a specific UTC time of day, then every 24 h.

    :param first_time: 'HH:MM' in UTC
    :param enabled_platforms: list of platform names to include in the digest
    """
    _enabled = enabled_platforms or []
    now      = datetime.utcnow()
    hr, mn   = map(int, first_time.split(":"))
    first_dt = datetime.combine(now.date(), dt_time(hour=hr, minute=mn))
    if first_dt < now:
        first_dt += timedelta(days=1)
    delay = (first_dt - now).total_seconds()
    logger.info("First daily digest scheduled at %s UTC", first_dt.isoformat())
    threading.Timer(delay, _digest_runner, args=[_enabled]).start()


def _digest_runner(enabled_platforms: list[str]):
    send_daily_digest(enabled_platforms)
    threading.Timer(24 * 3600, _digest_runner, args=[enabled_platforms]).start()
