import os
import time
import csv
import json
import threading
import asyncio
import yagmail

from datetime import datetime, timedelta, time as dt_time
from logging import getLogger, Formatter, StreamHandler
from logging.handlers import TimedRotatingFileHandler
from dotenv import load_dotenv
from psnawp_api import PSNAWP
from psnawp_api.utils import BASE_PATH, API_PATH


# Xbox WebAPI imports
from xbox.webapi.common.signed_session import SignedSession
from xbox.webapi.authentication.manager import AuthenticationManager
from xbox.webapi.api.client import XboxLiveClient
from xbox.webapi.authentication.models import OAuth2TokenResponse

# ----------------------------------------------------------------------------
# Load configuration & credentials
# ----------------------------------------------------------------------------
load_dotenv()  # pulls .env into os.environ

# Email creds\EMAIL_USER = creds["email_address"]
EMAIL_USER = os.getenv("EMAIL_USER")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")

# Xbox Azure AD creds from .env
XBOX_CLIENT_ID     = os.environ["XBOX_CLIENT_ID"]
XBOX_CLIENT_SECRET = os.environ["XBOX_SECRET_VALUE"]
XBOX_REDIRECT_URI  = os.environ.get("XBOX_REDIRECT_URI", "http://localhost/auth/callback")

daily_errors = {"PlayStation": [], "Xbox": []}

# Build Xbox WebAPI client
def init_xbox_client():
    # Prepare OAuth session
    session = SignedSession()
    auth = AuthenticationManager(session, XBOX_CLIENT_ID, XBOX_CLIENT_SECRET, XBOX_REDIRECT_URI)

    # Determine token storage path in local directory and ensure directory exists
    token_file = os.path.join(os.getcwd(), "xbox_tokens.json")
    token_dir = os.path.dirname(token_file)
    os.makedirs(token_dir, exist_ok=True)

    # Load existing tokens or perform interactive authentication
    if os.path.exists(token_file):
        with open(token_file, "r") as f:
            auth.oauth = OAuth2TokenResponse.model_validate_json(f.read())
    else:
        url = auth.generate_authorization_url()
        print("Go to this URL and paste code:", url)
        code = input("Code> ")
        auth.oauth = asyncio.get_event_loop().run_until_complete(
            auth.request_oauth_token(code)
        )
        with open(token_file, "w") as f:
            f.write(auth.oauth.model_dump_json())

    # Refresh tokens and persist updates
    asyncio.get_event_loop().run_until_complete(auth.refresh_tokens())
    with open(token_file, "w") as f:
        f.write(auth.oauth.model_dump_json())

    return XboxLiveClient(auth)

# Initialize clients
yag = yagmail.SMTP(EMAIL_USER, password=EMAIL_PASSWORD)
psnawp = PSNAWP(os.environ["PSN_API_KEY"])
psn_client = psnawp.me()
xbl_client = init_xbox_client()

# ----------------------------------------------------------------------------
# Constants & State
# ----------------------------------------------------------------------------
DATA_DIR = "data"
LOGS_DIR = "logs/api_collector"
for d in (DATA_DIR, LOGS_DIR): os.makedirs(d, exist_ok=True)

POLL_INTERVAL      = 300         # 5 min
API_KEY_WARN_DELAY = 3*7*24*3600 # 3 weeks
last_capture_time  = {"PlayStation":time.monotonic(), "Xbox":time.monotonic()}
escalation_state   = {"PlayStation":0,          "Xbox":0}
psn_last_status   = {}   # accountId -> last presenceState
psn_last_trophies = {}   # accountId -> last trophy JSON string
xbox_last_status   = {}
last_status = {}  # maps (platform, accountID) → (state, text, platform)

# ----------------------------------------------------------------------------
# Logging setup
# ----------------------------------------------------------------------------
logger = getLogger("orchestrator_api")
logger.setLevel("DEBUG")
handler = TimedRotatingFileHandler(os.path.join(LOGS_DIR,f"log-{datetime.utcnow():%Y-%m-%d}.log"),when="midnight",backupCount=14)
handler.setFormatter(Formatter("%(asctime)s [%(levelname)s] %(message)s","%Y-%m-%d %H:%M:%S"))
logger.addHandler(handler)
console=StreamHandler(); console.setFormatter(handler.formatter); logger.addHandler(console)

# ----------------------------------------------------------------------------
# Email helper
def send_email(subject, body):
    logger.info(f"Sending email: {subject}")
    try: yag.send(to=EMAIL_USER, subject=subject, contents=body)
    except Exception as e: logger.error(f"Email failed: {e}")


def send_daily_digest():
    """
    Collect stats for the past 24h and email them, including any errors.
    """
    cutoff = datetime.utcnow() - timedelta(days=1)
    logger.info("Digest cutoff time: %s", cutoff.isoformat())

    platforms    = ["PlayStation", "Xbox"]
    unique_users = {p: set() for p in platforms}
    updates      = {p: 0   for p in platforms}

    # Count rows & unique users in each <platform>-<user>.csv
    for fname in os.listdir(data_dir):
        if not fname.endswith(".csv"):
            continue
        platform = fname.split("-", 1)[0]
        if platform not in platforms:
            continue
        path = os.path.join(data_dir, fname)
        with open(path) as f:
            reader = csv.DictReader(f)
            for row in reader:
                ts = datetime.fromisoformat(row["time"])
                if ts >= cutoff:
                    unique_users[platform].add(row["userName"])
                    updates[platform] += 1

    # Build email body
    lines = [f"Daily Telemetry Digest ({datetime.utcnow().date()} UTC)\n"]
    for p in platforms:
        lines.append(f"{p}: {len(unique_users[p])} unique users, {updates[p]} updates")
    lines.append("")  # blank line

    # Append any errors from the last 24h
    for p in platforms:
        errs = daily_errors.get(p, [])
        if errs:
            lines.append(f"{p} errors:")
            for e in errs:
                lines.append(f"- {e}")
            lines.append("")

    subject = "Daily Telemetry Digest"
    body    = "\n".join(lines)
    logger.info("Sending daily digest email with subject: %s", subject)
    try:
        yag.send(subject=subject, contents=body)
        logger.info("Daily digest email sent successfully.")
    except Exception as e:
        logger.error("Failed to send daily digest email: %s", e)

    # Reset error log for next day
    for p in platforms:
        daily_errors[p].clear()

def schedule_digest(first_time="09:00"):
    """
    Schedule the first digest at a specific time of day (UTC), then every 24h.
    :param first_time: string 'HH:MM' in UTC
    """
    now = datetime.utcnow()
    hr, mn = map(int, first_time.split(":"))
    first_dt = datetime.combine(now.date(), dt_time(hour=hr, minute=mn))
    if first_dt < now:
        first_dt += timedelta(days=1)
    delay = (first_dt - now).total_seconds()

    logger.info(f"Scheduling first daily digest at {first_dt.isoformat()} UTC)")
    threading.Timer(delay, _digest_runner).start()

def _digest_runner():
    send_daily_digest()
    # schedule the next one in exactly 24h
    threading.Timer(24*3600, _digest_runner).start()

# ----------------------------------------------------------------------------
# CSV persistence
# ----------------------------------------------------------------------------
def update_person_csv(rows, platform):
    fieldnames=["platform","time","userName","accountID","presenceState","presenceText","presencePlatform","titleId","gamerScore","multiplayerSummary","lastSeen"]
    for r in rows:
        fn=os.path.join(DATA_DIR,f"{platform}-{r['userName']}.csv")
        ex=os.path.exists(fn)
        with open(fn,'a',newline='') as f:
            w=csv.DictWriter(f,fieldnames=fieldnames)
            if not ex: w.writeheader()
            w.writerow({k:r.get(k,'') for k in fieldnames})

# ----------------------------------------------------------------------------
# PSN scraper (unchanged)
# ----------------------------------------------------------------------------
def fetch_playstation():
    logger.debug("[PSN] Entering fetch_playstation()")
    friends     = list(psn_client.friends_list())
    account_ids = [f.account_id for f in friends]

    # 1) Batch-presences call
    base = BASE_PATH.get("profile_uri", "").rstrip("/")
    path = API_PATH.get("basic_presences", "")
    url  = f"{base}/{path}"
    params = {
        "type":                "primary",
        "accountIds":          ",".join(account_ids),
        "platforms":           "PS4,PS5,MOBILE_APP,PSPC",
        "withOwnGameTitleInfo":"true",
    }
    try:
        resp = psn_client.authenticator.get(url=url, params=params)
        resp.raise_for_status()
        batch = resp.json().get("basicPresences", [])
        logger.debug(f"[PSN] Batch returned {len(batch)} entries")
        last_capture_time["PlayStation"] = time.monotonic()
    except Exception as e:
        logger.error(f"[PSN] Batch presences failed: {e}")
        return

    pres_map = {p["accountId"]: p for p in batch if "accountId" in p}
    rows     = []
    ts       = datetime.utcnow().isoformat()

    for friend in friends:
        aid  = friend.account_id
        pres = pres_map.get(aid, {})
        info = pres.get("primaryPlatformInfo", {}) or {}
        game = pres.get("gameTitleInfoList", {}) or {}

        state = info.get("onlineStatus", "")
        prev  = psn_last_status.get(aid)
        psn_last_status[aid] = state

        # if no change AND not first run, skip
        if prev is not None and prev == state:
            continue

        # decide trophy_json
        trophy_json = psn_last_trophies.get(aid, "{}")
        # only fetch fresh trophies on an actual transition _to_ offline _after_ first run
        if prev is not None and prev != "offline" and state == "offline":
            try:
                user_obj = psnawp.user(online_id=friend.online_id, account_id=aid)
                if hasattr(user_obj, "get_profile_legacy"):
                    prof = user_obj.get_profile_legacy()
                else:
                    prof = user_obj.get_profile()
                # convert to dict
                if hasattr(prof, "model_dump"):
                    data = prof.model_dump()
                elif hasattr(prof, "dict"):
                    data = prof.dict()
                else:
                    data = dict(prof)

                block = data.get("profile", {}).get("profile", {}) or {}
                trophy = block.get("trophySummary", {}) or {}
                trophy_json = json.dumps(trophy, sort_keys=True)
                psn_last_trophies[aid] = trophy_json
                logger.debug(f"[PSN:{aid}] Fetched trophies on offline: {trophy_json}")
            except Exception as e:
                logger.error(f"[PSN:{aid}] Trophy fetch failed: {e}")
            time.sleep(1)

        # build row
        rows.append({
            "platform":          "PlayStation",
            "time":              ts,
            "userName":          friend.online_id,
            "accountID":         aid,
            "presenceState":     state,
            "presenceText":      game.get("titleName", ""),
            "presencePlatform":  game.get("launchPlatform", ""),
            "titleId":           game.get("npTitleId", ""),
            "gamerScore":        trophy_json,
            "multiplayerSummary":"",
            "lastSeen":          info.get("lastOnlineDate", "")
        })

    if rows:
        logger.debug(f"[PSN] Writing {len(rows)} rows to CSV")
        update_person_csv(rows, "PlayStation")


# ----------------------------------------------------------------------------
# Xbox-WebAPI integration (async)
# ----------------------------------------------------------------------------
async def get_friends_data():
    """
    Fetch Xbox friends and build mapping dictionaries,
    including rich presence text & multiplayer info.
    """
    raw_response = await xbl_client.people.get_friends_own()
    data = raw_response[1] if isinstance(raw_response, tuple) and len(raw_response) > 1 else raw_response
    friends = getattr(data, "people", data)

    xuids = []
    gtmap = {}
    score_map = {}
    last_map = {}

    # NEW maps for the rich fields
    text_map     = {}
    platform_map = {}
    title_map    = {}
    multi_map    = {}

    for f in friends:
        xuid = getattr(f, "xuid", None) or getattr(f, "userId", None)
        xuids.append(xuid)

        # basic maps
        gtmap[xuid]    = getattr(f, "gamertag", None) or getattr(f, "display_name", "")
        score_map[xuid]= str(getattr(f, "gamer_score", None) or getattr(f, "gamerScore", "") or "")
        last_dt = getattr(f, "last_seen_date_time_utc", None) or getattr(f, "lastSeenDateTimeUtc", None)
        last_map[xuid] = last_dt.isoformat() if isinstance(last_dt, datetime) else (last_dt or "")

        # --- pull the rich presence info off Person f ---
        # presence text
        text_map[xuid] = getattr(f, "presence_text", "") or ""
        # platform/device
        platform_map[xuid] = getattr(f, "presence_devices", None) or ""
        # title they were in (first detail if present)
        details = getattr(f, "presence_details", None) or []
        title_map[xuid] = (getattr(details[0], "title_id", "") if details else "") or ""
        # multiplayer summary
        msum = getattr(f, "multiplayer_summary", None)
        if msum:
            multi_map[xuid] = f"in_party={msum.in_party},in_multiplayer={msum.in_multiplayer_session}"
        else:
            multi_map[xuid] = ""

    return xuids, gtmap, score_map, last_map, text_map, platform_map, title_map, multi_map

def process_presence(pres_list, gtmap, score_map, last_map,
                     text_map, platform_map, title_map, multi_map,
                     check_time):
    """
    Process each presence entry into a CSV row, change‐detecting on full
    (state, text, platform) but ignoring updates where ONLY the
    presenceText moved from one 'Last seen...' to another.
    """
    rows = []
    for p in pres_list:
        xuid = getattr(p, "xuid", None) or getattr(p, "userId", None)
        key = ("Xbox", xuid)
        user = gtmap.get(xuid, "<unknown>")

        # 1) Extract the three tracked values
        state = getattr(p, "state", None) or ""
        text = text_map.get(xuid, "") or ""
        platform = platform_map.get(xuid, "") or ""

        new_vals = (state, text, platform)
        old_vals = last_status.get(key)

        # 2) If we’ve seen this user before and the only change is in
        #    presenceText AND both old/new start with “Last seen”, skip it.
        if old_vals is not None:
            same_state    = old_vals[0] == state
            same_platform = old_vals[2] == platform
            both_last_seen = old_vals[1].startswith("Last seen") and text.startswith("Last seen")
            if same_state and same_platform and both_last_seen:
                continue

        # 3) If anything changed, record and emit
        if old_vals is None or old_vals != new_vals:
            last_status[key] = new_vals

            rows.append({
                "platform":           "Xbox",
                "time":               check_time,
                "userName":           user,
                "accountID":          xuid,
                "presenceState":      state,
                "presenceText":       text,
                "presencePlatform":   platform,
                "titleId":            title_map.get(xuid, ""),
                "gamerScore":         score_map.get(xuid, ""),
                "multiplayerSummary": multi_map.get(xuid, ""),
                "lastSeen":           last_map.get(xuid, "")
            })

    return rows

async def fetch_xbox():
    logger.debug("[Xbox] Entering fetch_xbox()")

    # 1) Grab everything, including rich maps
    xuids, gtmap, score_map, last_map, \
    text_map, platform_map, title_map, multi_map = await get_friends_data()

    # 2) Batch-presence
    try:
        pres_list = await xbl_client.presence.get_presence_batch(xuids)
        logger.debug(f"[Xbox] Received presence list of length {len(pres_list)}")
        last_capture_time["Xbox"] = time.monotonic()
    except Exception as e:
        logger.error(f"[Xbox] Error in get_presence_batch: {e}")
        return

    # 3) Process & write
    check_time = datetime.utcnow().isoformat()
    rows = process_presence(
        pres_list,
        gtmap, score_map, last_map,
        text_map, platform_map, title_map, multi_map,
        check_time
    )

    if rows:
        logger.debug(f"[Xbox] Writing {len(rows)} rows to CSV")
        update_person_csv(rows, "Xbox")
    else:
        logger.debug("[Xbox] No rows to write")

# Sync wrapper for legacy loop
def fetch_xbox_telemetry():
    """Synchronous entrypoint for Xbox telemetry polling"""
    asyncio.get_event_loop().run_until_complete(fetch_xbox())

# ----------------------------------------------------------------------------
# Monitoring & scheduling
def alert_monitor():
    while True:
        time.sleep(60)
        now=time.monotonic()
        for plat in last_capture_time:
            el=now-last_capture_time[plat]; st=escalation_state[plat]
            if st==0 and el>2*POLL_INTERVAL+60: send_email(f"No telemetry from {plat}",f"{plat} silent {el:.0f}s"); escalation_state[plat]=1
            elif st==1 and el>3*POLL_INTERVAL+60: send_email(f"Continued outage for {plat}",f"{plat} silent {el:.0f}s"); escalation_state[plat]=2

def api_key_warning_runner():
    send_email("Rotate PSN_API_KEY","3 weeks—update PSN_API_KEY in .env.")
    threading.Timer(API_KEY_WARN_DELAY,api_key_warning_runner).start()

# ----------------------------------------------------------------------------
# Main loop
# ----------------------------------------------------------------------------
if __name__=="__main__":
    threading.Thread(target=alert_monitor,daemon=True).start()
    threading.Timer(API_KEY_WARN_DELAY,api_key_warning_runner).start()

    schedule_digest("09:00")
    logger.info("Starting polling…")
    while True:
        try:
            fetch_playstation()
            time.sleep(2)
            fetch_xbox_telemetry()
        except Exception as e:
            logger.error(f"Error: {e}")

        now = time.monotonic()
        remainder = now % POLL_INTERVAL  # Calculate time passed since the epoch remainder with respect to frequency
        sleep_time = POLL_INTERVAL - remainder

        if sleep_time < 120:
            logger.info(f"[HOST] Cycle complete. Waiting {sleep_time + POLL_INTERVAL:.0f} seconds until next cycle...")
            time.sleep(sleep_time + POLL_INTERVAL)
        else:
            logger.info(f"[HOST] Cycle complete. Waiting {sleep_time:.0f} seconds until next cycle...")
            time.sleep(sleep_time)
