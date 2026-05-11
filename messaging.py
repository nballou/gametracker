"""
Context-aware WhatsApp messaging via Twilio.

Monitors a specific participant's presence CSV and fires WhatsApp template
messages when they come online, go offline, or switch games. Designed to
run as a standalone process alongside orchestrator.py.

Configuration is at the top of this file — update PLATFORM, FRIEND_NAME,
and the Twilio template SIDs before use.
"""

import csv
import json
import logging
import os
import time
from dataclasses import dataclass

from dotenv import load_dotenv
from twilio.rest import Client

load_dotenv()

logger = logging.getLogger("gametracker.messaging")

# ── Settings ──────────────────────────────────────────────────────────────────
PLATFORM    = "PlayStation"
FRIEND_NAME = "nbballou"
DATA_DIR    = "data"

TWILIO_ACCOUNT_SID = os.getenv("TWILIO_ACCOUNT_SID")
TWILIO_AUTH_TOKEN  = os.getenv("TWILIO_AUTH_TOKEN")
TWILIO_FROM        = os.getenv("TWILIO_NUMBER")
WHATSAPP_TO        = "whatsapp:+447367525567"

# Flip to True once Twilio template approval comes through
USE_PENDING_TEMPLATES = False

# Approved/pending template SIDs
CONTENT_TEMPLATE_START = "HX5a8cc2d0e96fe74eed6f8d4b90e620ca"  # 3 vars: name, game, participant_id
CONTENT_TEMPLATE_END   = "HX3b2c185cfeb18c56192ff8f282ad035e"  # 1 var:  participant_id
BASIC_INVITE_SID       = "HX3a609e60d56b27858bf573111b9d6827"  # fallback, 3 vars

TEMPLATE_VAR_NAME           = "Nick"
TEMPLATE_VAR_PARTICIPANT_ID = "P000123"

POLL_SECONDS     = 10
COOLDOWN_SECONDS = 60   # minimum gap between outgoing messages
# ─────────────────────────────────────────────────────────────────────────────


@dataclass
class Presence:
    state: str
    title: str


_last_send_time = 0.0


def _wa(addr: str) -> str:
    return addr if addr.startswith("whatsapp:") else f"whatsapp:{addr}"


def _send_template(template_sid: str, vars_: dict, label: str):
    global _last_send_time
    now = time.monotonic()
    if now - _last_send_time < COOLDOWN_SECONDS:
        logger.info("[cooldown] skipping %s (%.1fs since last send)", label, now - _last_send_time)
        return
    logger.info("[twilio] sending %s via %s with vars %s", label, template_sid, vars_)
    try:
        client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
        client.messages.create(
            from_=_wa(TWILIO_FROM),
            to=WHATSAPP_TO,
            content_sid=template_sid,
            content_variables=json.dumps(vars_),
        )
        _last_send_time = now
        logger.info("[sent] %s OK", label)
    except Exception as e:
        logger.error("[error] Twilio send failed for %s: %s", label, e)


def send_template_start(game_name: str):
    if USE_PENDING_TEMPLATES:
        _send_template(
            CONTENT_TEMPLATE_START,
            {"1": TEMPLATE_VAR_NAME, "2": game_name or "(unknown)", "3": TEMPLATE_VAR_PARTICIPANT_ID},
            "start(pending)",
        )
    else:
        _send_template(
            BASIC_INVITE_SID,
            {"1": TEMPLATE_VAR_NAME, "2": "1", "3": TEMPLATE_VAR_PARTICIPANT_ID},
            "start(basic)",
        )


def send_template_end():
    if USE_PENDING_TEMPLATES:
        _send_template(
            CONTENT_TEMPLATE_END,
            {"1": TEMPLATE_VAR_PARTICIPANT_ID},
            "end(pending)",
        )
    else:
        _send_template(
            BASIC_INVITE_SID,
            {"1": TEMPLATE_VAR_NAME, "2": "1", "3": TEMPLATE_VAR_PARTICIPANT_ID},
            "end(basic)",
        )


def _csv_path() -> str:
    return os.path.join(DATA_DIR, f"{PLATFORM}-{FRIEND_NAME}.csv")


def _read_last_presence() -> Presence | None:
    path = _csv_path()
    if not os.path.exists(path):
        return None
    last_row = None
    with open(path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            last_row = row
    if not last_row:
        return None
    return Presence(
        state=(last_row.get("presenceState") or "").strip().lower(),
        title=(last_row.get("presenceText") or "").strip(),
    )


def main():
    logger.info("Watching %s for %s on %s…", _csv_path(), FRIEND_NAME, PLATFORM)
    while not os.path.exists(_csv_path()):
        logger.info("Waiting for CSV to appear…")
        time.sleep(POLL_SECONDS)

    last = _read_last_presence()
    logger.info("Baseline presence: %s", last)

    while True:
        time.sleep(POLL_SECONDS)
        current = _read_last_presence()
        if current is None:
            continue

        logger.debug("state='%s', title='%s'", current.state, current.title)

        if last and current.state == last.state and current.title == last.title:
            continue

        logger.info("Change detected: %s → %s", last, current)

        if last:
            if (last.state == "offline" or not last.state) and current.state != "offline":
                logger.info("OFFLINE → ONLINE, starting '%s'", current.title)
                send_template_start(current.title)

            elif last.state != "offline" and current.state == "offline":
                logger.info("ONLINE → OFFLINE, ending '%s'", last.title)
                send_template_end()

            elif (last.state != "offline" and current.state != "offline"
                  and current.title != last.title):
                logger.info("Game switch: '%s' → '%s'", last.title, current.title)
                send_template_end()
                send_template_start(current.title)

        last = current


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    main()
