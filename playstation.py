"""
PlayStation friends-list presence tracking via psnawp.

Call init() once at startup, then call fetch() each polling cycle.
fetch() returns a list of row dicts (one per detected state change);
rows are empty if nothing changed or if the batch call fails (raises).
"""

import json
import logging
import time
from datetime import datetime

from psnawp_api import PSNAWP
from psnawp_api.utils import BASE_PATH, API_PATH

logger = logging.getLogger("gametracker.playstation")

# Module-level client state, set by init()
_psnawp     = None
_psn_client = None

# Per-friend state tracking across poll cycles
_last_status   = {}  # accountId → last presenceState string
_last_trophies = {}  # accountId → last trophy summary JSON string


def init(api_key: str | None):
    """Initialize the PSN client. Must be called before fetch()."""
    global _psnawp, _psn_client
    _psnawp     = PSNAWP(api_key)
    _psn_client = _psnawp.me()
    logger.info("PSN client initialized")


def fetch() -> list[dict]:
    """
    Poll the PSN friends list for presence changes.

    Uses the basicPresences batch endpoint to minimize API calls.
    Only emits rows for friends whose presence state has changed since
    the last poll. On first run, emits a row for every friend.

    Trophy data is fetched (once) when a friend transitions to offline,
    to capture the session's final game.

    Raises on API errors so orchestrator.py can update error state.
    """
    logger.debug("Entering fetch()")
    friends     = list(_psn_client.friends_list())
    account_ids = [f.account_id for f in friends]

    # Batch presence lookup
    base   = BASE_PATH.get("profile_uri", "").rstrip("/")
    path   = API_PATH.get("basic_presences", "")
    url    = f"{base}/{path}"
    params = {
        "type":                 "primary",
        "accountIds":           ",".join(account_ids),
        "platforms":            "PS4,PS5,MOBILE_APP,PSPC",
        "withOwnGameTitleInfo": "true",
    }
    try:
        resp = _psn_client.authenticator.get(url=url, params=params)
        resp.raise_for_status()
        batch = resp.json().get("basicPresences", [])
        logger.debug("Batch returned %d entries", len(batch))
    except Exception as e:
        logger.error("Batch presences failed: %s", e)
        raise

    pres_map = {p["accountId"]: p for p in batch if "accountId" in p}
    rows     = []
    ts       = datetime.utcnow().isoformat()

    for friend in friends:
        aid  = friend.account_id
        pres = pres_map.get(aid, {})
        info = pres.get("primaryPlatformInfo", {}) or {}
        game = (pres.get("gameTitleInfoList") or [{}])[0]

        state = info.get("onlineStatus", "")
        prev  = _last_status.get(aid)
        _last_status[aid] = state

        # No change since last poll (skip first-run check via `prev is not None`)
        if prev is not None and prev == state:
            continue

        # Fetch trophy summary when a friend goes offline (captures session end)
        trophy_json = _last_trophies.get(aid, "{}")
        if prev is not None and prev != "offline" and state == "offline":
            try:
                user_obj = _psnawp.user(online_id=friend.online_id, account_id=aid)
                prof = (user_obj.get_profile_legacy()
                        if hasattr(user_obj, "get_profile_legacy")
                        else user_obj.get_profile())
                data   = (prof.model_dump() if hasattr(prof, "model_dump")
                          else prof.dict()  if hasattr(prof, "dict")
                          else dict(prof))
                trophy = ((data.get("profile", {}).get("profile", {}) or {})
                          .get("trophySummary", {}) or {})
                trophy_json         = json.dumps(trophy, sort_keys=True)
                _last_trophies[aid] = trophy_json
                logger.debug("[%s] Trophies captured on offline: %s", aid, trophy_json)
            except Exception as e:
                logger.error("[%s] Trophy fetch failed: %s", aid, e)
            time.sleep(1)

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
            "multiplayerSummary": "",
            "lastSeen":          info.get("lastOnlineDate", ""),
        })

    logger.debug("%d rows collected", len(rows))
    return rows
