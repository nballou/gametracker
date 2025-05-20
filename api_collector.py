import os
import time
import csv
import json
import threading
import asyncio
import yagmail

from datetime import datetime
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
psn_last_status    = {}
xbox_last_status   = {}

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

    # 1) Gather friends & IDs
    friends     = list(psn_client.friends_list())
    account_ids = [f.account_id for f in friends]
    logger.debug(f"[PSN] Friend account IDs: {account_ids}")

    # 2) Build batch-presences URL without double-slash
    profile_base = BASE_PATH.get("profile_uri", "").rstrip("/")
    pres_path    = API_PATH.get("basic_presences", "")
    if not profile_base or not pres_path:
        logger.error("[PSN] Missing BASE_PATH or API_PATH for batch presences")
        return

    presences_url = f"{profile_base}/{pres_path}"

    # 3) Fire batch-presences request
    params = {
        "type": "primary",
        "accountIds": ",".join(account_ids),
        "platforms": "PS4,PS5,MOBILE_APP,PSPC",
        "withOwnGameTitleInfo": "true",
    }
    try:
        resp = psn_client.authenticator.get(url=presences_url, params=params)
        resp.raise_for_status()
        payload = resp.json()
        batch_list = payload.get("basicPresences", [])
        logger.debug(f"[PSN] Batch returned {len(batch_list)} entries")
        # turn that list into a mapping accountId → presence dict
        all_presences = {
            p.get("accountId"): p.get("basicPresence", p)
            for p in batch_list
            if p.get("accountId")
        }
        batch_success = True
    except Exception as e:
        logger.error(f"[PSN] Batch presences call failed: {e}")
        all_presences = {}
        batch_success = False

    rows = []
    check_time = datetime.utcnow().isoformat()

    # 4) Process each friend
    for friend in friends:
        aid = friend.account_id

        # choose batch vs per-friend
        if batch_success and aid in all_presences:
            pres = all_presences[aid]
        else:
            try:
                raw = psnawp.user(online_id=friend.online_id, account_id=aid) \
                             .get_presence()
                pres = raw.get("basicPresence", raw)
                logger.debug(f"[PSN] Using per-friend get_presence for {aid}: {pres!r}")
            except Exception as e:
                logger.error(f"[PSN] Per-friend get_presence failed for {aid}: {e}")
                pres = {}

        # 4a) Fetch & dictify full profile
        try:
            profile_resp = psnawp.user(online_id=friend.online_id, account_id=aid) \
                                 .get_profile_legacy()
            full_profile = (
                profile_resp.model_dump()
                if hasattr(profile_resp, "model_dump")
                else (profile_resp if isinstance(profile_resp, dict) else {})
            )
        except Exception as e:
            logger.error(f"[PSN] get_profile_legacy failed for {aid}: {e}")
            full_profile = {}

        # 4b) Drill into nested profile
        outer     = full_profile.get("profile", {}) or {}
        inner     = outer.get("profile") or outer
        prof_block = inner or {}

        # 4c) Serialize trophySummary
        trophy_summary = prof_block.get("trophySummary", {})
        try:
            trophy_json = json.dumps(trophy_summary, sort_keys=True)
        except Exception as e:
            logger.error(f"[PSN] Error serializing trophy_summary: {e}")
            trophy_json = "{}"

        # 4d) Extract presence fields
        basic         = pres.get("basicPresence", pres)
        info          = basic.get("primaryPlatformInfo", {})
        console_state = info.get("onlineStatus", "") or ""
        console_last  = info.get("lastOnlineDate", "") or ""
        console_avail = basic.get("availability", "") or ""

        # mobile fallback
        mobile_state = mobile_last = None
        mobile_list  = prof_block.get("presences", [])
        if mobile_list:
            m = mobile_list[0]
            mobile_state = m.get("onlineStatus")
            mobile_last  = m.get("lastOnlineDate") or m.get("lastAvailableDate")

        state_to_record = (
            mobile_state
            if mobile_state and mobile_state not in ("offline", "unavailable")
            else console_state or console_avail
        )
        last_to_record = mobile_last or console_last

        # 4e) Assemble CSV row
        row = {
            "platform": "PlayStation",
            "time": check_time,
            "userName": friend.online_id,
            "accountID": aid,
            "presenceState": state_to_record,
            "presenceText": console_avail,
            "presencePlatform": info.get("platform", "") or "",
            "titleId": "",
            "gamerScore": trophy_json,
            "multiplayerSummary": "",
            "lastSeen": last_to_record
        }

        prev = psn_last_status.get(friend.online_id)
        if row["presenceState"] != prev:
            psn_last_status[friend.online_id] = row["presenceState"]
            rows.append(row)

        time.sleep(1)  # throttle between per-friend profile calls

    # 5) Persist changes
    if rows:
        logger.debug(f"[PSN] Writing {len(rows)} rows to CSV")
        update_person_csv(rows, "PlayStation")
        last_capture_time["PlayStation"] = time.monotonic()


# ----------------------------------------------------------------------------
# Xbox-WebAPI integration (async)
# ----------------------------------------------------------------------------
async def fetch_xbox():
    logger.debug("[Xbox] Entering fetch_xbox()")

    # 1) Retrieve friends list
    raw_response = await xbl_client.people.get_friends_own()
    # print(f"[Xbox] raw_response: {raw_response}")

    # Unpack tuple if returned
    data = raw_response[1] if isinstance(raw_response, tuple) and len(raw_response) > 1 else raw_response
    # Extract list of friends
    friends = getattr(data, 'people', data)

    # 2) Build XUIDs and mapping, plus gamerScore & lastSeen from friend data
    xuids = []
    gtmap = {}
    score_map = {}
    last_map = {}
    for f in friends:
        xuid = getattr(f, 'xuid', None) or getattr(f, 'userId', None)
        gamertag = getattr(f, 'gamertag', None)
        # friend-level stats
        score = getattr(f, 'gamer_score', None) or getattr(f, 'gamerScore', None) or getattr(f, 'gamer_score', None)
        last_seen_friend = getattr(f, 'last_seen_date_time_utc', None) or getattr(f, 'lastSeenDateTimeUtc', None)
        if isinstance(last_seen_friend, datetime):
            last_seen_friend = last_seen_friend.isoformat()

        xuids.append(xuid)
        gtmap[xuid] = gamertag
        score_map[xuid] = score or ''
        last_map[xuid] = last_seen_friend or ''

    # 3) Batch-presence query
    try:
        pres_list = await xbl_client.presence.get_presence_batch(xuids)
        logger.debug("[Xbox] Received presence list of length {len(pres_list)}")
    except Exception as e:
        logger.error(f"[Xbox] Error in get_presence_batch: {e}")
        return

    # 4) Process each presence
    rows = []
    check_time = datetime.utcnow().isoformat()
    for idx, p in enumerate(pres_list):

        xuid = getattr(p, 'xuid', None) or getattr(p, 'userId', None)
        user = gtmap.get(xuid, '<unknown>')
        state = getattr(p, 'state', None) or getattr(p, 'presenceState', None)
        last = getattr(p, 'lastSeen', None) or ''

        prev = xbox_last_status.get(xuid)
        if state != prev:
            # logger.debug(f"[Xbox] State changed for {xuid}: {prev} -> {state}")
            xbox_last_status[xuid] = state
            rows.append({
                "platform": "Xbox",
                "time": check_time,
                "userName": user,
                "accountID": xuid,
                "presenceState": state,
                "presenceText": "",
                "presencePlatform": "",
                "titleId": "",
                "gamerScore": score_map.get(xuid, ''),
                "multiplayerSummary": "",
                "lastSeen": last_map.get(xuid, '')
            })

    # 5) Write CSV if needed
    if rows:
        logger.debug(f"[Xbox] Writing {len(rows)} rows to CSV")
        update_person_csv(rows, "Xbox")
        last_capture_time["Xbox"] = time.monotonic()
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
