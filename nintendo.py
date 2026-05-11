"""
Nintendo Switch friends-list presence tracking — placeholder module.

INTENDED APPROACH
-----------------
nxapi (https://gitlab.fancy.org.uk/samuel/nxapi) exposes Nintendo Switch
friend presence via its CLI. The relevant command is:

    nxapi users friends --json

which returns a JSON array of friend objects including online/offline status
and the title they are currently playing. The library does not expose a
Python API — it must be invoked as a subprocess.

A minimal implementation would look like:

    import subprocess, json

    def fetch() -> list[dict]:
        result = subprocess.run(
            ["nxapi", "users", "friends", "--json"],
            capture_output=True, text=True, check=True
        )
        friends = json.loads(result.stdout)
        # ... map fields to the shared row schema ...

OPEN QUESTIONS
--------------
1. Authentication
   nxapi handles Nintendo's coral/znca token exchange internally but
   requires an initial interactive login (`nxapi auth`). How tokens persist
   across process restarts (cache path, refresh behaviour on expiry) is not
   yet confirmed.

2. Output schema
   The exact JSON structure from `nxapi users friends --json` has not been
   captured and mapped to the shared row format used by playstation.py and
   xbox.py. Fields of interest: online status, current title, last-seen time.

3. API stability
   nxapi depends on Nintendo's undocumented coral/znca APIs, which have
   changed before. Rate limits and session expiry behaviour are unknown.

4. Integration pattern
   Subprocess invocation adds latency and process-management overhead. A
   tighter integration with nxapi's internals (e.g. via its TypeScript/Node
   modules) may be cleaner long-term, but would require a different
   interop approach.

TODO
----
- Run `nxapi users friends --json` and capture example output
- Define field mapping to the shared CSV schema
- Implement init() / fetch() with subprocess call and error handling
- Clarify token refresh / re-auth behaviour
"""

import logging

logger = logging.getLogger("gametracker.nintendo")


def init():
    """Placeholder — Nintendo tracking not yet implemented."""
    logger.warning("Nintendo tracking is not yet implemented; skipping init.")


def fetch() -> list[dict]:
    """Placeholder — Nintendo tracking not yet implemented."""
    logger.warning("Nintendo tracking is not yet implemented; returning empty list.")
    return []
