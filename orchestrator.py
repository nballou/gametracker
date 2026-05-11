"""
Gametracker orchestrator — entry point and shared infrastructure.

Handles logging, CSV persistence, the alert monitor, and the main polling
loop. Platform modules (playstation.py, xbox.py, nintendo.py) are imported
here; toggle collection on/off with the flags below.

Run with:
    python orchestrator.py
"""

import csv
import os
import threading
import time
from logging import Formatter, StreamHandler, getLogger
from logging.handlers import TimedRotatingFileHandler

from dotenv import load_dotenv

import digest
import nintendo
import playstation
import xbox

load_dotenv()

# ── Platform toggles ──────────────────────────────────────────────────────────
ENABLE_PLAYSTATION = True
ENABLE_XBOX        = True
ENABLE_NINTENDO    = False   # not yet implemented; see nintendo.py

# ── Configuration ─────────────────────────────────────────────────────────────
DATA_DIR  = "data"
LOGS_DIR  = "logs"
POLL_INTERVAL      = 300              # seconds between polling cycles
API_KEY_WARN_DELAY = 3 * 7 * 24 * 3600  # remind to rotate PSN key after 3 weeks

for d in (DATA_DIR, LOGS_DIR):
    os.makedirs(d, exist_ok=True)

# ── Logging ───────────────────────────────────────────────────────────────────
# Root logger for this package; platform child loggers (gametracker.playstation
# etc.) inherit this configuration automatically.
logger = getLogger("gametracker")
logger.setLevel("DEBUG")
log_path = os.path.join(LOGS_DIR, "gametracker.log")
_handler = TimedRotatingFileHandler(log_path, when="midnight", backupCount=14, utc=True)
_handler.setFormatter(Formatter(
    "%(asctime)s [%(levelname)s] %(name)s: %(message)s", "%Y-%m-%d %H:%M:%S"
))
logger.addHandler(_handler)
_console = StreamHandler()
_console.setFormatter(_handler.formatter)
logger.addHandler(_console)

# ── Shared state ──────────────────────────────────────────────────────────────
last_capture_time = {p: time.monotonic() for p in ("PlayStation", "Xbox", "Nintendo")}
escalation_state  = {p: 0               for p in ("PlayStation", "Xbox", "Nintendo")}

# ── CSV persistence ───────────────────────────────────────────────────────────
_FIELDNAMES = [
    "platform", "time", "userName", "accountID",
    "presenceState", "presenceText", "presencePlatform",
    "titleId", "gamerScore", "multiplayerSummary", "lastSeen",
]

def update_person_csv(rows: list[dict], platform: str):
    """Append presence rows to per-user CSV files under DATA_DIR."""
    for row in rows:
        path   = os.path.join(DATA_DIR, f"{platform}-{row['userName']}.csv")
        exists = os.path.exists(path)
        with open(path, "a", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=_FIELDNAMES)
            if not exists:
                writer.writeheader()
            writer.writerow({k: row.get(k, "") for k in _FIELDNAMES})

# ── Alert monitor ─────────────────────────────────────────────────────────────
def _alert_monitor():
    """Background thread: escalating email alerts when a platform goes silent."""
    while True:
        time.sleep(60)
        now = time.monotonic()
        for platform in last_capture_time:
            elapsed = now - last_capture_time[platform]
            state   = escalation_state[platform]
            if state == 0 and elapsed > 2 * POLL_INTERVAL + 60:
                digest.send_email(f"No telemetry from {platform}",
                                  f"{platform} silent for {elapsed:.0f}s")
                escalation_state[platform] = 1
            elif state == 1 and elapsed > 3 * POLL_INTERVAL + 60:
                digest.send_email(f"Continued outage: {platform}",
                                  f"{platform} silent for {elapsed:.0f}s")
                escalation_state[platform] = 2


def _api_key_warning_runner():
    digest.send_email("Rotate PSN_API_KEY",
                      "3 weeks since startup — update PSN_API_KEY in .env.")
    threading.Timer(API_KEY_WARN_DELAY, _api_key_warning_runner).start()

# ── Main polling loop ─────────────────────────────────────────────────────────
if __name__ == "__main__":
    required = ["EMAIL_USER", "EMAIL_PASSWORD"]
    if ENABLE_PLAYSTATION:
        required.append("PSN_API_KEY")
    if ENABLE_XBOX:
        required += ["XBOX_CLIENT_ID", "XBOX_SECRET_VALUE"]
    missing = [k for k in required if not os.getenv(k)]
    if missing:
        raise RuntimeError(f"Missing environment variables: {', '.join(missing)}")

    enabled_platforms = [p for p, en in [("PlayStation", ENABLE_PLAYSTATION),
                                          ("Xbox",        ENABLE_XBOX),
                                          ("Nintendo",    ENABLE_NINTENDO)] if en]

    # Initialise digest module and platform clients
    digest.init(
        data_dir=DATA_DIR,
        email_user=os.getenv("EMAIL_USER"),
        email_password=os.getenv("EMAIL_PASSWORD"),
    )
    digest.daily_errors.update({p: [] for p in enabled_platforms})

    if ENABLE_PLAYSTATION:
        playstation.init(os.getenv("PSN_API_KEY"))
    if ENABLE_XBOX:
        xbox.init()
    if ENABLE_NINTENDO:
        nintendo.init()

    threading.Thread(target=_alert_monitor, daemon=True).start()
    threading.Timer(API_KEY_WARN_DELAY, _api_key_warning_runner).start()
    digest.schedule_digest("09:00", enabled_platforms=enabled_platforms)

    logger.info(
        "Starting polling — PlayStation=%s, Xbox=%s, Nintendo=%s",
        ENABLE_PLAYSTATION, ENABLE_XBOX, ENABLE_NINTENDO,
    )

    platforms = [
        ("PlayStation", ENABLE_PLAYSTATION, playstation),
        ("Xbox",        ENABLE_XBOX,        xbox),
        ("Nintendo",    ENABLE_NINTENDO,    nintendo),
    ]

    while True:
        for platform, enabled, module in platforms:
            if not enabled:
                continue
            try:
                rows = module.fetch()
                if rows:
                    update_person_csv(rows, platform)
                last_capture_time[platform] = time.monotonic()
                escalation_state[platform]  = 0   # reset on successful fetch
            except Exception as e:
                logger.error("[%s] fetch failed: %s", platform, e)
                digest.daily_errors.setdefault(platform, []).append(str(e))

        now        = time.monotonic()
        sleep_time = POLL_INTERVAL - (now % POLL_INTERVAL)
        if sleep_time < 120:
            sleep_time += POLL_INTERVAL
        logger.info("[HOST] Cycle complete. Sleeping %.0fs.", sleep_time)
        time.sleep(sleep_time)
