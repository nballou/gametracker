import os
import time
import csv
import json
from dataclasses import dataclass
from twilio.rest import Client
from dotenv import load_dotenv
load_dotenv()

# ── SETTINGS ────────────────────────────────────────────────────────────────
PLATFORM      = "PlayStation"                 # "PlayStation" or "Xbox"
FRIEND_NAME   = "nbballou"
DATA_DIR      = "data"

TWILIO_ACCOUNT_SID = os.getenv("TWILIO_ACCOUNT_SID")
TWILIO_AUTH_TOKEN  = os.getenv("TWILIO_AUTH_TOKEN")
TWILIO_FROM        = os.getenv("TWILIO_NUMBER")
WHATSAPP_TO        = "whatsapp:+447367525567"

# Templates
CONTENT_TEMPLATE_START = "HX5a8cc2d0e96fe74eed6f8d4b90e620ca"  # start template (3 vars)
CONTENT_TEMPLATE_END   = "HX3b2c185cfeb18c56192ff8f282ad035e"  # end template (1 var)

TEMPLATE_VAR_NAME           = "Nick"
TEMPLATE_VAR_PARTICIPANT_ID = "P000123"

POLL_SECONDS = 10
COOLDOWN_SECONDS = 60  # one message per minute
# ────────────────────────────────────────────────────────────────────────────

@dataclass
class Presence:
    state: str
    title: str

_last_send_time = 0.0

def _wa(addr: str) -> str:
    return addr if addr.startswith("whatsapp:") else f"whatsapp:{addr}"

def send_template_start(game_name: str):
    """Start message: 3 variables — name, game, participant_id"""
    _send_template(CONTENT_TEMPLATE_START, {
        "1": TEMPLATE_VAR_NAME,
        "2": game_name or "(unknown)",
        "3": TEMPLATE_VAR_PARTICIPANT_ID,
    }, "start")

def send_template_end():
    """End message: 1 variable — participant_id only"""
    _send_template(CONTENT_TEMPLATE_END, {
        "1": TEMPLATE_VAR_PARTICIPANT_ID,
    }, "end")

def _send_template(template_sid: str, vars_: dict, label: str):
    global _last_send_time
    now = time.monotonic()
    if now - _last_send_time < COOLDOWN_SECONDS:
        print(f"[cooldown] skipping {label}")
        return

    client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
    client.messages.create(
        from_=_wa(TWILIO_FROM),
        to=WHATSAPP_TO,
        content_sid=template_sid,
        content_variables=json.dumps(vars_),
    )
    _last_send_time = now
    print(f"[sent] {label} message")

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

    while True:
        time.sleep(POLL_SECONDS)
        current = read_last_presence()
        if current is None:
            continue

        if last and current.state == last.state and current.title == last.title:
            continue

        if last:
            # OFFLINE → ONLINE (session start)
            if (last.state == "offline" or not last.state) and current.state != "offline":
                try:
                    send_template_start(current.title)
                    print(f"[alert] START → {current.title!r}")
                except Exception as e:
                    print(f"[alert] send failed: {e}")

            # ONLINE → OFFLINE (session end)
            elif last.state != "offline" and current.state == "offline":
                try:
                    send_template_end()
                    print(f"[alert] END → {last.title!r}")
                except Exception as e:
                    print(f"[alert] send failed: {e}")

            # ONLINE → ONLINE with different game (switch = end+start)
            elif last.state != "offline" and current.state != "offline" and current.title != last.title:
                try:
                    send_template_end()
                    send_template_start(current.title)
                    print(f"[alert] SWITCH → {last.title!r} → {current.title!r}")
                except Exception as e:
                    print(f"[alert] send failed: {e}")

        last = current

if __name__ == "__main__":
    main()
