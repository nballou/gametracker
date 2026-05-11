# gametracker

**Status: work in progress.** This repository tracks friends' gaming presence across PlayStation, Xbox, and (eventually) Nintendo Switch, using each platform's friends-list presence API. It is being handed off to the RSE team at an early stage — the core functionality works, but the codebase is not yet production-ready.

---

## What it does

`orchestrator.py` polls the friends lists of authenticated accounts on each enabled platform at a configurable interval (default: 5 minutes). When a friend's presence state changes (offline → online, game switch, online → offline), a row is appended to a per-user CSV file in `data/`. A background thread sends email alerts if a platform goes silent, and a daily digest email summarises activity.

`messaging.py` is a separate process that watches a specific participant's CSV and sends WhatsApp messages via Twilio when they come online or go offline. This is study-specific and not integrated into the main polling loop.

---

## Platform status

| Platform    | Library                                                                 | Status                        |
|-------------|-------------------------------------------------------------------------|-------------------------------|
| PlayStation | [psnawp](https://github.com/isFakeAccount/psnawp)                       | Working                       |
| Xbox        | [xbox-webapi-python](https://github.com/OpenXbox/xbox-webapi-python)    | Working                       |
| Nintendo    | [nxapi](https://gitlab.fancy.org.uk/samuel/nxapi)                       | Placeholder — see `nintendo.py` |

---

## Architecture

```
orchestrator.py   — entry point: logging, CSV writing, alert monitor, polling loop
digest.py         — email utilities: send_email, daily digest, scheduling
playstation.py    — PSN client init and fetch()
xbox.py           — Xbox client init and fetch()
nintendo.py       — stub; documents intended approach and open questions
messaging.py      — standalone WhatsApp notifier (Twilio, study-specific)
data/             — per-user CSV files (<Platform>-<username>.csv)
logs/             — rotating daily log files
```

Each platform module exposes two functions:

- `init(...)` — initialise the API client (called once at startup)
- `fetch()` — poll for presence changes, return a list of row dicts

Orchestrator calls `fetch()` for each enabled platform, writes any returned rows to CSV, and resets the alert timer. To toggle a platform, set the flags near the top of `orchestrator.py`:

```python
ENABLE_PLAYSTATION = True
ENABLE_XBOX        = True
ENABLE_NINTENDO    = False   # not yet implemented
```

---

## Setup

### Requirements

```
psnawp
xbox-webapi
yagmail
twilio
python-dotenv
```

### Environment variables

Copy `.env.example` to `.env` (or set these in your environment):

```
EMAIL_USER=
EMAIL_PASSWORD=

PSN_API_KEY=           # NPSSO token from PlayStation; rotate every ~3 weeks
XBOX_CLIENT_ID=        # Azure AD app client ID
XBOX_SECRET_VALUE=     # Azure AD app client secret
XBOX_REDIRECT_URI=     # defaults to http://localhost/auth/callback
```

For `messaging.py`:

```
TWILIO_ACCOUNT_SID=
TWILIO_AUTH_TOKEN=
TWILIO_NUMBER=         # Twilio WhatsApp sender number
```

### Xbox authentication

On first run, `xbox.py` will print an OAuth URL and prompt for the auth code. The resulting token is cached to `xbox_tokens.json` and refreshed automatically on subsequent runs.

### Running

```bash
# Main presence tracker
python orchestrator.py

# WhatsApp notifier (separate process)
python messaging.py
```

---

## Data format

Each CSV has the following columns:

| Column             | Description                                         |
|--------------------|-----------------------------------------------------|
| `platform`         | PlayStation / Xbox / Nintendo                       |
| `time`             | UTC ISO timestamp of the state change               |
| `userName`         | PSN online ID or Xbox gamertag                      |
| `accountID`        | Platform account ID                                 |
| `presenceState`    | online / offline (platform-specific strings)        |
| `presenceText`     | Game title or rich presence text                    |
| `presencePlatform` | Device (PS5, Xbox Series X, etc.)                  |
| `titleId`          | Platform title/game ID                              |
| `gamerScore`       | Trophy summary JSON (PSN) or gamerscore (Xbox)      |
| `multiplayerSummary` | Party/multiplayer session info (Xbox)             |
| `lastSeen`         | Last-seen timestamp (when available)                |

---

## Known limitations and open issues

- **Nintendo is not implemented.** `nxapi` must be called as a CLI subprocess; the JSON schema, authentication persistence, and rate limits are not yet characterised. See `nintendo.py` for details.
- **PSN API key rotation.** The NPSSO token used by `psnawp` expires; the orchestrator will email a reminder after 3 weeks.
- **Xbox token refresh.** Token refresh works, but re-auth after full token expiry requires the interactive OAuth flow to be run again manually.
- **No deduplication on restart.** If the process restarts, the first poll cycle emits rows for all friends regardless of whether their state actually changed.
- **Single-account per platform.** The current design authenticates as one account per platform and tracks that account's friends list. Multi-account support would require refactoring the module-level state in each platform module.
- **`messaging.py` is study-specific.** Hardcoded friend name, participant ID, and Twilio template SIDs need updating for different participants.
