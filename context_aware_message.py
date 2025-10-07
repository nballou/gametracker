import os
import time
import csv
import json
from dataclasses import dataclass
from twilio.rest import Client
from dotenv import load_dotenv
load_dotenv()

# ── SETTINGS ────────────────────────────────────────────────────────────────
PLATFORM      = "PlayStation"
FRIEND_NAME   = "nbballou"
DATA_DIR      = "data"

TWILIO_ACCOUNT_SID = os.getenv("TWILIO_ACCOUNT_SID")
TWILIO_AUTH_TOKEN  = os.getenv("TWILIO_AUTH_TOKEN")
TWILIO_FROM        = os.getenv("TWILIO_NUMBER")
WHATSAPP_TO        = "whatsapp:+447367525567"

# Toggle between approved templates vs fallback BASIC_INVITE
USE_PENDING_TEMPLATES = False  # ← flip True when templates approved

# Pending templates
CONTENT_TEMPLATE_START = "HX5a8cc2d0e96fe74eed6f8d4b90e620ca"  # 3 vars
CONTENT_TEMPLATE_END   = "HX3b2c185cfeb18c56192ff8f282ad035e"  # 1 var

# Temporary fallback template (used when USE_PENDING_TEMPLATES=False)
BASIC_INVITE_SID = "HX3a609e60d56b27858bf573111b9d6827"       # 3 vars

# Variables
TEMPLATE_VAR_NAME           = "Nick"
TEMPLATE_VAR_PARTICIPANT_ID = "P000123"

POLL_SECONDS      = 10
COOLDOWN_SECONDS  = 60  # one message per minute
# ────────────────────────────────────────────────────────────────────────────

@dataclass
class Presence:
    state: str
    title: str

_last_send_time = 0.0

def _wa(addr: str) -> str:
    return addr if addr.startswith("whatsapp:") else f"whatsapp:{addr}"

def send_template_start(game_name: str):
    """Send start message based on toggle."""
    if USE_PENDING_TEMPLATES:
        _send_template(
            CONTENT_TEMPLATE_START,
            {"1": TEMPLATE_VAR_NAME, "2": (game_name or "(unknown)"), "3": TEMPLATE_VAR_PARTICIPANT_ID},
            "start(pending)"
        )
    else:
        _send_template(
            BASIC_INVITE_SID,
            {"1": TEMPLATE_VAR_NAME, "2": "1", "3": TEMPLATE_VAR_PARTICIPANT_ID},
            "start(basic)"
        )

def send_template_end():
    """Send end message based on toggle."""
    if USE_PENDING_TEMPLATES:
        _send_template(
            CONTENT_TEMPLATE_END,
            {"1": TEMPLATE_VAR_PARTICIPANT_ID},
            "end(pending)"
        )
    else:
        _send_template(
            BASIC_INVITE_SID,
            {"1": TEMPLATE_VAR_NAME, "2": "1", "3": TEMPLATE_VAR_PARTICIPANT_ID},
            "end(basic)"
        )

def _send_template(template_sid: str, vars_: dict, label: str):
    global _last_send_time
    now = time.monotonic()
    if now - _last_send_time < COOLDOWN_SECONDS:
        print(f"[cooldown] skipping {label}, only {now - _last_send_time:.1f}s since last send")
        return

    print(f"[twilio] sending {label} message using {template_sid} with vars {vars_}")
    try:
        client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
        client.messages.create(
            from_=_wa(TWILIO_FROM),
            to=WHATSAPP_TO,
            content_sid=template_sid,
            content_variables=json.dumps(vars_),
        )
        _last_send_time = now
        print(f"[sent] {label} message OK")
    except Exception as e:
        print(f"[error] Twilio send failed for {label}: {e}")

def csv_path() -> str:
    return os.path.join(DATA_DIR, f"{PLATFORM}-{FRIEND_NAME}.csv")

def read_last_presence() -> Presence | None:
    path = csv_path()
    if not os.path.exists(path):
        return None
    last_row = None
    with open(path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            last_row = row
    if not last_row:
        return None
    state = (last_row.get("presenceState") or "").strip().lower()
    title = (last_row.get("presenceText") or "").strip()
    return Presence(state=state, title=title)

def main():
    print(f"[monitor] watching {csv_path()} for {FRIEND_NAME} on {PLATFORM}…")
    while not os.path.exists(csv_path()):
        print("[monitor] waiting for CSV to appear…")
        time.sleep(POLL_SECONDS)

    last = read_last_presence()
    print(f"[init] baseline presence: {last}")

    while True:
        time.sleep(POLL_SECONDS)
        current = read_last_presence()
        if current is None:
            continue

        # log every check
        print(f"[poll] current status: state='{current.state}', title='{current.title}'")

        # no change → no message
        if last and current.state == last.state and current.title == last.title:
            continue

        print(f"[change] detected: {last} → {current}")

        if last:
            # OFFLINE → ONLINE (session start)
            if (last.state == "offline" or not last.state) and current.state != "offline":
                print(f"[transition] OFFLINE→ONLINE, starting '{current.title}'")
                send_template_start(current.title)

            # ONLINE → OFFLINE (session end)
            elif last.state != "offline" and current.state == "offline":
                print(f"[transition] ONLINE→OFFLINE, ending '{last.title}'")
                send_template_end()

            # ONLINE → ONLINE with different game (switch)
            elif last.state != "offline" and current.state != "offline" and current.title != last.title:
                print(f"[transition] GAME SWITCH '{last.title}' → '{current.title}'")
                send_template_end()
                send_template_start(current.title)

        last = current

if __name__ == "__main__":
    main()
