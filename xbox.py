"""
Xbox friends-list presence tracking via xbox-webapi-python.

Call init() once at startup (handles OAuth token load/refresh), then
call fetch() each polling cycle. fetch() returns a list of row dicts
(one per detected state change); raises on API errors.

First run requires interactive browser authentication if no token file exists.
Tokens are cached to xbox_tokens.json in the working directory.
"""

import asyncio
import logging
import os
from datetime import datetime

from xbox.webapi.api.client import XboxLiveClient
from xbox.webapi.authentication.manager import AuthenticationManager
from xbox.webapi.authentication.models import OAuth2TokenResponse
from xbox.webapi.common.signed_session import SignedSession

logger = logging.getLogger("gametracker.xbox")

_xbl_client  = None
_last_status = {}  # ("Xbox", xuid) → (state, presenceText, presencePlatform)


def init():
    """Initialize the Xbox Live client. Must be called before fetch()."""
    global _xbl_client
    _xbl_client = _build_client()
    logger.info("Xbox client initialized")


def _build_client() -> XboxLiveClient:
    client_id     = os.getenv("XBOX_CLIENT_ID")
    client_secret = os.getenv("XBOX_SECRET_VALUE")
    redirect_uri  = os.getenv("XBOX_REDIRECT_URI", "http://localhost/auth/callback")

    session = SignedSession()
    auth    = AuthenticationManager(session, client_id, client_secret, redirect_uri)
    token_file = os.path.join(os.getcwd(), "xbox_tokens.json")

    if os.path.exists(token_file):
        with open(token_file) as f:
            auth.oauth = OAuth2TokenResponse.model_validate_json(f.read())
    else:
        url  = auth.generate_authorization_url()
        print("Open this URL and paste the auth code back here:", url)
        code = input("Code> ")
        auth.oauth = asyncio.get_event_loop().run_until_complete(
            auth.request_oauth_token(code)
        )
        with open(token_file, "w") as f:
            f.write(auth.oauth.model_dump_json())

    asyncio.get_event_loop().run_until_complete(auth.refresh_tokens())
    with open(token_file, "w") as f:
        f.write(auth.oauth.model_dump_json())

    return XboxLiveClient(auth)


def fetch() -> list[dict]:
    """
    Poll the Xbox friends list for presence changes.

    Returns rows only for friends whose (state, presenceText, presencePlatform)
    tuple has changed. Suppresses churn caused by 'Last seen...' text updates
    when the player is already offline.

    Raises on API errors so orchestrator.py can update error state.
    """
    return asyncio.get_event_loop().run_until_complete(_fetch_async())


async def _fetch_async() -> list[dict]:
    logger.debug("Entering fetch()")

    (xuids, gtmap, score_map, last_map,
     text_map, platform_map, title_map, multi_map) = await _get_friends_data()

    try:
        pres_list = await _xbl_client.presence.get_presence_batch(xuids)
        logger.debug("Received %d presence entries", len(pres_list))
    except Exception as e:
        logger.error("get_presence_batch failed: %s", e)
        raise

    check_time = datetime.utcnow().isoformat()
    return _process_presence(
        pres_list, gtmap, score_map, last_map,
        text_map, platform_map, title_map, multi_map, check_time
    )


async def _get_friends_data():
    raw     = await _xbl_client.people.get_friends_own()
    data    = raw[1] if isinstance(raw, tuple) and len(raw) > 1 else raw
    friends = getattr(data, "people", data)

    xuids, gtmap, score_map, last_map = [], {}, {}, {}
    text_map, platform_map, title_map, multi_map = {}, {}, {}, {}

    for f in friends:
        xuid = getattr(f, "xuid", None) or getattr(f, "userId", None)
        xuids.append(xuid)

        gtmap[xuid]     = getattr(f, "gamertag", None) or getattr(f, "display_name", "")
        score_map[xuid] = str(getattr(f, "gamer_score", None) or getattr(f, "gamerScore", "") or "")

        last_dt        = (getattr(f, "last_seen_date_time_utc", None)
                          or getattr(f, "lastSeenDateTimeUtc", None))
        last_map[xuid] = last_dt.isoformat() if isinstance(last_dt, datetime) else (last_dt or "")

        text_map[xuid]     = getattr(f, "presence_text", "") or ""
        platform_map[xuid] = getattr(f, "presence_devices", None) or ""

        details         = getattr(f, "presence_details", None) or []
        title_map[xuid] = (getattr(details[0], "title_id", "") if details else "") or ""

        msum = getattr(f, "multiplayer_summary", None)
        multi_map[xuid] = (
            f"in_party={msum.in_party},in_multiplayer={msum.in_multiplayer_session}"
            if msum else ""
        )

    return xuids, gtmap, score_map, last_map, text_map, platform_map, title_map, multi_map


def _process_presence(pres_list, gtmap, score_map, last_map,
                       text_map, platform_map, title_map, multi_map,
                       check_time) -> list[dict]:
    """
    Emit a row per friend whose tracked state tuple has changed.

    Suppresses updates where state and platform are unchanged and both
    old and new presenceText begin with 'Last seen' (Xbox rotates this
    string frequently for offline friends).
    """
    rows = []
    for p in pres_list:
        xuid     = getattr(p, "xuid", None) or getattr(p, "userId", None)
        key      = ("Xbox", xuid)
        state    = getattr(p, "state", None) or ""
        text     = text_map.get(xuid, "") or ""
        platform = platform_map.get(xuid, "") or ""
        new_vals = (state, text, platform)
        old_vals = _last_status.get(key)

        # Suppress 'Last seen...' text churn while state and platform are unchanged
        if old_vals is not None:
            if (old_vals[0] == state
                    and old_vals[2] == platform
                    and old_vals[1].startswith("Last seen")
                    and text.startswith("Last seen")):
                continue

        if old_vals is None or old_vals != new_vals:
            _last_status[key] = new_vals
            rows.append({
                "platform":           "Xbox",
                "time":               check_time,
                "userName":           gtmap.get(xuid, "<unknown>"),
                "accountID":          xuid,
                "presenceState":      state,
                "presenceText":       text,
                "presencePlatform":   platform,
                "titleId":            title_map.get(xuid, ""),
                "gamerScore":         score_map.get(xuid, ""),
                "multiplayerSummary": multi_map.get(xuid, ""),
                "lastSeen":           last_map.get(xuid, ""),
            })

    return rows
