import frida
import subprocess
import time
from datetime import datetime, time as dt_time, timedelta
import sys
import csv
import os
import io
import random
import logging
from logging.handlers import TimedRotatingFileHandler
import xml.etree.ElementTree as ET
import requests
import yagmail
import threading
import json
import warnings
import re

# Email settings
with open("credentials.json", "r") as cred_file:
    creds = json.load(cred_file)
yag = yagmail.SMTP(creds["email_address"], password=creds["password"])

# Directory to save CSV files locally (adjust as needed)
data_dir = "data"
if not os.path.exists(data_dir):
    os.makedirs(data_dir)

# Configuration: digest frequency and optional first digest time of day (HH:MM in 24-hour)
# Latter can be set to None or a string 'HH:MM'. If None, first digest is sent immediately.
digest_interval_hours = 12 # how often to send the daily digest email
first_digest_time = None  # e.g. '08:30' for 8:30 AM, or None for now

# Scraping and alert settings.
frequency = 180 # how often, in seconds, to cycle between apps
refresh_threshold = 15  # seconds without telemetry before swipe
alert_check_interval = 60 # seconds between each check.
reopen_timeout = 2 * frequency + alert_check_interval  # seconds before restarting the app if telemetry is not received.
reboot_timeout = 3 * frequency + alert_check_interval  # seconds before rebooting the device if telemetry is still not received.
recovery_timeout = 4 * frequency + alert_check_interval   # seconds to wait *after* a reboot before sending a failure alert.

# Alert-related global variables and initializations
reboot_event = threading.Event()
last_status = {} # initialize the last_status dictionary
state_lock = threading.Lock()
restart_count = 0
reboot_count  = 0

# setup frida gadget
GADGET_LOCAL_PATH  = "apks/libfg.so"
GADGET_DEVICE_PATH = "/data/local/tmp/libfg.so"

# -----------------------------------------------------------------------------
# Logging configuration and functions
# -----------------------------------------------------------------------------

class DailyRotatingFileHandler(TimedRotatingFileHandler):
    def doRollover(self):
        super().doRollover()
        # recompute baseFilename for the new date
        new_base = os.path.join(
            logs_dir,
            f"log-{datetime.utcnow():%Y-%m-%d}.log"
        )
        self.baseFilename = new_base
        # reopen the stream on the new file
        if getattr(self, "stream", None):
            self.stream.close()
        self.stream = self._open()

def namer(default_name):
    """
    Default name example: "logs/log-2025-04-08.log.2025-04-09"
    We want this to be: "logs/log-2025-04-09.log"
    """
    base_dir, fname = os.path.split(default_name)
    parts = fname.split('.')
    if len(parts) >= 3:
        new_name = f"log-{parts[2]}.log"
        return os.path.join(base_dir, new_name)
    else:
        return default_name

# Ensure the logs/ directory exists.
logs_dir = "logs"
if not os.path.exists(logs_dir):
    os.makedirs(logs_dir)

# Compute today's date (YYYY-MM-DD) and use it in the base filename.
today = datetime.utcnow().strftime("%Y-%m-%d")
base_log_filename = os.path.join(logs_dir, f"log-{today}.log")

# Set up a TimedRotatingFileHandler so that the logs are rotated at midnight.
handler = DailyRotatingFileHandler(base_log_filename, when="midnight", backupCount=14)
handler.suffix = "%Y-%m-%d"
handler.namer  = namer

# log without milliseconds.
formatter = logging.Formatter(
    '%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
formatter.converter = time.gmtime
handler.setFormatter(formatter)

# Set up the logger.
logger = logging.getLogger("orchestrator")
logger.setLevel(logging.DEBUG)
logger.addHandler(handler)

# Also output logs to the console.
consoleHandler = logging.StreamHandler()
consoleHandler.setFormatter(formatter)
consoleHandler.setLevel(logging.DEBUG)
logger.addHandler(consoleHandler)

logger.info("Logger configured: logs stored in logs/ as log-YYYY-MM-DD.log with timestamps without milliseconds.")

# -----------------------------------------------------------------------------
# Alert configuration and functions
# -----------------------------------------------------------------------------

# Global variable to hold the timestamp (in seconds) of the last telemetry capture.
last_capture_time = {
    "PlayStation": time.monotonic(),
    "Xbox": time.monotonic()
}
# Flags to track if an alert has already been sent.
alert_sent = {
    "PlayStation": False,
    "Xbox": False
}

# Escalation state for each platform: 0 = no escalation; 1 = app restarted; 2 = device rebooted; 3 = terminal state, alert sent.
escalation_state = {
    "PlayStation": 0,
    "Xbox": 0
}

# near the top
needs_restart = {
    "PlayStation": False,
    "Xbox":       False,
}
needs_reboot  = {
    "PlayStation": False,
    "Xbox":       False,
}

# near the top, alongside your globals
has_been_foregrounded = {
    "PlayStation": False,
    "Xbox":       False,
}



def on_message(message, data):
    """Handle messages sent from the Frida script."""
    if message["type"] == "send":
        payload = message["payload"]
        if payload.get("type") == "csv-data":
            # Retrieve CSV data from the payload.
            csv_data = payload.get("csv", "")
            platform = payload.get("platform", "")
            if csv_data:
                # logger.info(f"[HOST] Received CSV data from {platform}")
                update_last_capture(platform)
                # Process and append new rows only if there are status changes.
                process_csv_data(csv_data, platform)
            else:
                logger.info("[HOST] CSV data is empty.")
        else:
            logger.info("[HOST] Message from script:", payload)
    elif message["type"] == "error":
        logger.info("[HOST] Error message from script:", message["stack"])
    else:
        logger.info("[HOST] Other message:", message)

def update_last_capture(platform):
    """
    Update the last capture time for the specified platform.
    This function is called when telemetry is received.
    """
    logger.info(f"[HOST] Received telemetry from {platform}.")

    global last_capture_time, escalation_state
    # thread-safe reset of the platform’s state
    with state_lock:
        last_capture_time[platform] = time.monotonic()
        escalation_state[platform] = 0

def send_alert_email(subject, body):
    """
    Sends an alert email.
    """
    logger.info("Sending alert email: %s", subject)
    try:
        yag.send(subject=subject, contents = body)
    except Exception as e:
        logger.error("Failed to send alert email: %s", e)

def send_daily_digest():
    global restart_count, reboot_count
    """
    Collect stats for the past 24h and email them.
    """

    cutoff = datetime.utcnow() - timedelta(days=1)
    logger.info("Digest cutoff time: %s", cutoff.isoformat())

    # tally unique users & updates per platform
    platforms = ["PlayStation", "Xbox"]
    unique_users = {p:set() for p in platforms}
    updates      = {p:0    for p in platforms}

    for fname in os.listdir(data_dir):
        if not fname.endswith(".csv"):
            continue
        platform = fname.split("-",1)[0]
        path     = os.path.join(data_dir, fname)
        with open(path) as f:
            reader = csv.DictReader(f)
            for row in reader:
                ts = datetime.fromisoformat(row["time"])
                if ts >= cutoff:
                    unique_users[platform].add(row["userName"])
                    updates[platform] += 1

    # build email body
    lines = []
    for p in platforms:
        lines.append(f"{p}: {len(unique_users[p])} unique users, {updates[p]} updates")
    lines.append(f"Restarts: {restart_count}")
    lines.append(f"Reboots: {reboot_count}")

    subject = "Daily Telemetry Digest"
    body    = "\n".join(lines)
    logger.info("Sending daily digest email with subject: %s", subject)
    try:
        yag.send(subject=subject, contents=body)
        logger.info("Daily digest email sent successfully.")
    except Exception as e:
        logger.error("Failed to send daily digest email: %s", e)

    restart_count = 0
    reboot_count  = 0

def schedule_digest(first_time=None):
    """
    Schedule the first digest at a specific time of day, then recurring every digest_interval_hours.
    :param first_time: datetime.time or string 'HH:MM'. If None, send immediately.
    """
    # Determine initial delay
    now = datetime.now()
    if first_time:
        if isinstance(first_time, str):
            hr, mn = map(int, first_time.split(':'))
            first_time = dt_time(hour=hr, minute=mn)
        # Build a datetime for today at the target time
        target = datetime.combine(now.date(), first_time)
        if target < now:
            # schedule for tomorrow
            target += timedelta(days=1)
        delay = (target - now).total_seconds()
    else:
        delay = digest_interval_hours * 3600

    logger.info(f"Scheduling first digest in {delay:.0f} seconds")
    threading.Timer(delay, _digest_runner).start()

def _digest_runner():
    send_daily_digest()
    # Schedule next run after fixed interval
    interval_seconds = digest_interval_hours * 3600
    logger.info(f"Scheduling next digest in {interval_seconds} seconds")
    threading.Timer(interval_seconds, _digest_runner).start()

def wait_for_boot(timeout=120):
    # Wait for adb to see the device
    subprocess.run(["adb", "wait-for-device"], check=True)
    # Then wait for Android to fully finish booting
    deadline = time.time() + timeout
    while time.time() < deadline:
        out = subprocess.check_output(
            ["adb", "shell", "getprop", "sys.boot_completed"],
            text=True
        ).strip()
        if out == '1':
            logger.info("Device boot completed.")
            return
        time.sleep(1)
    raise RuntimeError("Timed out waiting for device to boot")

def reboot_device(force = False):
    """Reboot the device using ADB."""
    if force:
        with state_lock:
            escalation_state["PlayStation"] = 2
            escalation_state["Xbox"] = 2

    if not force:
        # Check if the device is already in root mode.
        result = subprocess.run(["adb", "shell", "whoami"], capture_output=True, text=True)
        if "root" in result.stdout.strip():
            logger.info("[HOST] Device is already in root mode. Closing apps and proceeding...")
            close_app("com.scee.psxandroid")
            close_app("com.microsoft.xboxone.smartglass")
            time.sleep(2)
            return

    logger.info("[ADB] Rebooting device...")
    reboot_event.set()
    subprocess.run(["adb", "reboot"], check=True)
    wait_for_boot()
    subprocess.run(["adb", "root"], check=True)
    reboot_event.clear()
    logger.info("[ADB] Reboot complete.")

def alert_monitor():
    """
    Monitor telemetry timestamps. For each platform:
     - If no telemetry for reopen_timeout seconds and escalation state is 0:
         * Send an alert email and restart the app.
         * Set escalation state to 1.
     - If still no telemetry after reboot_timeout seconds and escalation state is 1:
         * Send another alert email and reboot the device.
         * Set escalation state for both platforms to 2.
    """
    global last_capture_time, escalation_state
    while True:
        time.sleep(alert_check_interval)
        now = time.monotonic()

        # Take a thread-safe snapshot of timestamps & states
        with state_lock:
            snapshot = list(last_capture_time.items())
            states   = escalation_state.copy()

        # Check each platform’s elapsed time and escalate as needed
        for platform, last_ts in snapshot:
            elapsed = now - last_ts
            state   = states[platform]

            # 1) No escalation yet → restart app if no telemetry for reopen_timeout
            if state == 0 and elapsed > reopen_timeout:
                logger.info("Marking %s for restart on next cycle", platform)
                needs_restart[platform] = True
                with state_lock:
                    escalation_state[platform] = 1

            # 2) Already restarted once → reboot device if still no telemetry by reboot_timeout
            elif state == 1 and elapsed > reboot_timeout:
                logger.info("Marking %s for reboot on next cycle", platform)
                needs_reboot[platform] = True
                with state_lock:
                    escalation_state[platform] = 2

            # 3) Already rebooted → final failure alert if still no telemetry by recovery_timeout
            elif state == 2 and elapsed > recovery_timeout:
                logger.info("No telemetry from %s after reboot; sending failure alert.", platform)
                send_alert_email(
                    subject=f"Telemetry Failure - {platform} - No Recovery",
                    body=f"No telemetry has resumed from {platform} within {recovery_timeout} seconds after reboot."
                )
                # Terminal “failed” state to prevent repeat alerts
                with state_lock:
                    escalation_state[platform] = 3
                        
# Start the alert monitoring thread as a daemon so it runs in the background.
alert_thread = threading.Thread(target=alert_monitor, daemon=True)
alert_thread.start()

def push_gadget():
    """
    Pushes the Frida-Gadget .so onto the device and makes it world-readable.
    """
    logger.info("Pushing Frida-Gadget to device…")
    subprocess.run([
        "adb", "push",
        GADGET_LOCAL_PATH,
        GADGET_DEVICE_PATH
    ], check=True)
    subprocess.run([
        "adb", "shell", "chmod", "644", GADGET_DEVICE_PATH
    ], check=True)
    logger.info("Frida-Gadget is in place at %s", GADGET_DEVICE_PATH)

# def kill_frida_server():
#     try:
#         subprocess.run(["adb", "shell", "pkill", "frida-server"], check=True)
#     except subprocess.CalledProcessError as e:
#         try:
#             subprocess.run(["adb", "shell", "killall", "frida-server"], check=True)
#             # logger.debug("Successfully ran killall frida-server.")
#         except subprocess.CalledProcessError as e:
#             pass
#     time.sleep(1)

# def start_frida_server():
#     """
#     Start Frida-server on the AVD.
#     This assumes that the frida-server binary is already on the device
#     at /data/local/tmp/ and has executable permissions.
#     """
#     logger.info("[HOST] Starting frida-server on device...")
#     # Use adb shell with su to start frida-server in the background.
#     command = "adb shell nohup /data/local/tmp/frida-server > /dev/null 2>&1 &"
#     subprocess.run(command, shell=True)
#     time.sleep(3)

# def wait_for_frida(timeout=30):
#     """
#     Poll until frida-server appears in the process list or until timeout.
#     Uses `pidof` which is more reliable than `ps|grep`.
#     """
#     for i in range(timeout):
#         try:
#             out = subprocess.check_output(
#                 "adb shell pidof frida-server", 
#                 shell=True, text=True
#             ).strip()
#             if out:
#                 logger.info(f"wait_for_frida: frida-server pid={out}")
#                 return True
#         except subprocess.CalledProcessError:
#             # pidof returns non-zero if not found
#             pass

#         # Optional: log each retry
#         logger.debug(f"wait_for_frida: attempt {i+1}/{timeout} – frida-server not yet up")
#         time.sleep(1)

#     return False

def enable_gadget_wrap(package):
    # This causes every subsequent "am start" of that package
    # to LD_PRELOAD our gadget .so.
    wrap_prop = f"wrap.{package}"
    preload   = f"LD_PRELOAD={GADGET_DEVICE_PATH}"
    subprocess.run([
        "adb", "shell", "setprop", wrap_prop, preload
    ], check=True)
    logger.info(f"Enabled Frida-Gadget wrap for {package}")

# def reboot_frida():
#     """
#     Reboot the frida-server on the device.
#     This is useful if the server has crashed or is unresponsive.
#     """
#     # logger.info("[HOST] Rebooting frida-server...")
#     start_frida_server()
#     if not wait_for_frida(30):
#         logger.error("Frida-server never came up after reboot!")
#         return
#     logger.info("Frida-server is running.")

def get_ui_dump():
    # Dump the UI hierarchy to the device's sdcard.
    subprocess.run(["adb", "shell", "uiautomator", "dump", "/sdcard/window_dump.xml"], check=True)
    # Retrieve the XML content from the device.
    result = subprocess.run(["adb", "shell", "cat", "/sdcard/window_dump.xml"],
                            stdout=subprocess.PIPE, check=True, text=True)
    return result.stdout

def is_friends_list_visible():
    xml_str = get_ui_dump()
    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError as e:
        print("Error parsing XML:", e)
        return False

    for elem in root.iter("node"):
        resource_id = elem.get("resource-id")
        if resource_id and "friend-list" in resource_id:
            return True
    return False

def process_csv_data(csv_str, platform):
    """
    Process CSV data received from Frida for a given platform.
    Only add new rows if the person's presenceState has changed.
    Also add a checkTimestamp and platform column.
    """
    global last_status
    new_rows = []
    now = datetime.utcnow().isoformat()
    f = io.StringIO(csv_str)
    reader = csv.DictReader(f)
    debug_count = 0
    for row in reader:
        unique_id = row.get("accountID")  # unique identifier for the user
        if not unique_id:
            logger.debug("Skipping row with empty unique_id: %s", row)
            continue
        key = (platform, unique_id)
        new_presence_state = row.get("presenceState", "")
        new_presence_text = row.get("presenceText", "")
        new_presence_platform = row.get("presencePlatform", "")
        new_values = (new_presence_state, new_presence_text, new_presence_platform)
        old_values = last_status.get(key, (None, None, None))
        # Ignore update if only change is in the "Last seen" presenceText.
        if (key in last_status and 
            old_values[0] == new_presence_state and 
            old_values[2] == new_presence_platform and 
            old_values[1].startswith("Last seen") and 
            new_presence_text.startswith("Last seen")):
            continue
        if key not in last_status or old_values != new_values:
            last_status[key] = new_values
            row["time"] = now
            new_rows.append(row)
            debug_count += 1

    if new_rows:
        update_person_csv(new_rows, platform)

def update_person_csv(new_rows, platform):
    """Append new rows to each person's individual CSV file."""
    fieldnames = [
        "platform",
        "time",
        "userName",
        "accountID",
        "presenceState",
        "presenceText",
        "presencePlatform",
        "titleID",
        "gamerScore",
        "multiplayerSummary",
        "lastSeen"
    ]
    changed_users = []
    for row in new_rows:
        userName = row.get("userName")
        if not userName:
            continue
        filename = os.path.join(data_dir, f"{platform}-{userName}.csv")
        file_exists = os.path.exists(filename)
        with open(filename, "a", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            if not file_exists:
                writer.writeheader()
                logger.debug("Creating new file and writing header to %s.", filename)
            writer.writerow({key: row.get(key, "") for key in fieldnames})
        changed_users.append(userName)
    
    # Single log entry listing all users whose status changed
    if changed_users:
        logger.info(
            "Recorded %d status update(s) for %s: [%s]",
            len(changed_users),
            platform,
            ", ".join(changed_users)
        )

def open_friends_tab(package):
    if package == "com.scee.psxandroid":
        time.sleep(5)
        subprocess.run(["adb", "shell", "input", "tap", "955", "200"]) # open friends tab
        time.sleep(5)

    if package == "com.microsoft.xboxone.smartglass":
        time.sleep(5)
        subprocess.run(["adb", "shell", "input", "tap", "320", "2190"]) # open friends tab
        time.sleep(5)

def launch_app(package, activity, timeout=10):
    """
    Launch the app with Frida-Gadget preloaded by using `sh -c` on the device.
    """
    # Build a shell command string for the device
    remote_cmd = (
        f"LD_PRELOAD={GADGET_DEVICE_PATH} "
        f"am start -n {package}/{activity}"
    )
    # Now wrap it with sh -c so it’ll parse the env var correctly
    cmd = [
        "adb", "shell",
        "sh", "-c",
        f"\"{remote_cmd}\""
    ]
    logger.info(f"[ADB] Launching {package} via sh -c with gadget (timeout={timeout}s)…")
    try:
        # shell=False here, passing the list directly
        subprocess.run(cmd, check=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        logger.warning(f"[ADB] launch_app timed out after {timeout}s")
    except subprocess.CalledProcessError as e:
        logger.error(f"[ADB] launch_app failed: {e}")

    open_friends_tab(package)

def close_app(package):
    """Close the app using ADB."""
    logger.info(f"[ADB] Closing {package}...")
    subprocess.run(
        ["adb", "shell", "am", "force-stop", package],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

def bring_to_foreground(package, activity):
    """Bring the app to the foreground using ADB."""
    # logger.info(f"[ADB] Bringing {package}/{activity} to foreground")
    subprocess.run(["adb", "shell", "am", "start", "-n", f"{package}/{activity}"])
    time.sleep(5)
    if package == "com.scee.psxandroid":
        if not is_friends_list_visible():
            logger.info(f"[ADB] Friends list not visible. Opening friends tab for {package}.")
            open_friends_tab(package)
    else: 
        open_friends_tab(package)

def prepare_app_for_scrape(platform_info):
    """
    1) Handle restart/reboot flags
    2) Bring app to foreground (or launch it)
    3) Swipe to refresh, but only after the first successful foreground
       and only if telemetry is stale.
    """
    name     = platform_info["name"]
    pkg      = platform_info["package"]
    activity = platform_info["activity"]

    # 1) Escalation: reboot or restart if flagged
    if needs_reboot[name]:
        reboot_device()
        needs_reboot[name] = False
    elif needs_restart[name]:
        close_app(pkg)
        launch_app(pkg, activity)
        needs_restart[name] = False

    # 2) launch / foreground with gadget prepended
    logger.info(f"[HOST] Launching {name} with Frida-Gadget preload…")
    cmd = (
        f"adb shell env LD_PRELOAD={GADGET_DEVICE_PATH} "
        f"am start -n {pkg}/{activity}"
    )
    subprocess.run(cmd, shell=True, check=True)
    time.sleep(5)  # let the UI settle

    # 3) Swipe logic
    if not has_been_foregrounded[name]:
        # very first time — no swipe
        logger.info(f"[HOST] First foreground of {name}; skipping swipe.")
        has_been_foregrounded[name] = True
    else:
        # after first time, only swipe if >15s since last telemetry
        elapsed = time.monotonic() - last_capture_time.get(name, 0)
        if elapsed > refresh_threshold:
            logger.info(
                f"[HOST] No new {name} telemetry for {elapsed:.1f}s → swiping to refresh"
            )
            swipe_down()
        else:
            logger.info(
                f"[HOST] {name} telemetry is fresh ({elapsed:.1f}s ago) → skip swipe"
            )


def swipe_down():
    """Perform a vertical swipe from a random position within the specified rectangle."""
    start_x = random.randint(150, 900)
    start_y = random.randint(600, 950)
    end_y = random.randint(1800, 2000)  # Ensure the swipe ends no lower than Y = 1800
    # logger.info(f"[ADB] Swiping from ({start_x}, {start_y}) to ({start_x}, {end_y})")
    subprocess.run(["adb", "shell", "input", "swipe", str(start_x), str(start_y), str(start_x), str(end_y)])

def swipe_if_stale(name):
    if not has_been_foregrounded[name]:
        logger.info(f"[HOST] First foreground of {name}; skipping swipe.")
        has_been_foregrounded[name] = True
        return

    elapsed = time.monotonic() - last_capture_time.get(name, 0)
    if elapsed > REFRESH_THRESHOLD:
        logger.info(f"[HOST] No new {name} telemetry for {elapsed:.1f}s → swiping")
        swipe_down()
    else:
        logger.info(f"[HOST] {name} telemetry is fresh ({elapsed:.1f}s ago) → skip swipe")


def is_app_running(device, app_alias):
    """Check if the app process is already running."""
    processes = device.enumerate_processes()  # Note: using snake_case method
    for proc in processes:
        if proc.name == app_alias:
            return True
    return False

def ensure_app_running(platform_info):
    """
    1) If flagged for full reboot, do that (and reset first-foreground logic).
    2) If flagged for soft restart, close & launch (and reset first-foreground).
    3) If already running and no flags, just foreground it.
    4) If not running at all, launch it.
    """
    name     = platform_info["name"]
    pkg      = platform_info["package"]
    alias    = platform_info["alias"]    # e.g. "PS App", but we'll use pkg for process checks
    activity = platform_info["activity"]

    device = frida.get_usb_device(timeout=5)

    # 1) Full device reboot pending?
    if needs_reboot[name]:
        reboot_device()
        needs_reboot[name] = False
        has_been_foregrounded[name] = False

    # 2) App-level restart pending?
    if needs_restart[name]:
        logger.info(f"[HOST] Restarting {name}…")
        close_app(pkg)
        launch_app(pkg, activity)
        needs_restart[name] = False
        has_been_foregrounded[name] = False
        return

    # 3) Is the process already up?
    if is_app_running(device, pkg):
        # Already running → just bring it forward
        logger.info(f"[HOST] Bringing {name} to foreground…")
        bring_to_foreground(pkg, activity)
    else:
        # Not running → fresh launch
        logger.info(f"[HOST] Launching {name} from scratch…")
        launch_app(pkg, activity)
        has_been_foregrounded[name] = False  # ensure swipe-skip on first launch


# def attach_frida_to_app(package_name, app_alias, activity, script_path, session_store):
    # """Attach Frida to the app process (spawn if needed) and load the provided script."""
    # device = frida.get_usb_device(timeout=5)
    # running = is_app_running(device, app_alias)
    
    # if running:
    #     try:
    #         process = device.get_process(app_alias)
    #         # bring app to foreground as before…
    #         with warnings.catch_warnings():
    #             warnings.simplefilter("ignore")
    #             bring_to_foreground(package_name, activity)
    #         time.sleep(5)

    #         # ← INSERT A 15-SECOND CHECK HERE BEFORE SWIPING ↓
    #         # map your app_alias ("PS App"/"Xbox") back to the telemetry key ("PlayStation"/"Xbox")
    #         if app_alias == "PS App":
    #             platform = "PlayStation"
    #         elif app_alias == "Xbox":
    #             platform = "Xbox"
    #         else:
    #             platform = None

    #         if platform is None or time.monotonic() - last_capture_time.get(platform, 0) > 15:
    #             swipe_down()
    #         else:
    #             logger.info(
    #                 "Skipping swipe_down for %s (last telemetry %.1fs ago)",
    #                 platform,
    #                 time.monotonic() - last_capture_time[platform]
    #             )
    #     except frida.ProcessNotFoundError as e:
    #         logger.info(f"[FRIDA] Process not found: {e}")
    #         # Process might have disappeared; spawn if necessary.
    #         running = False

    # if not running:
    #     logger.info(f"[FRIDA] {package_name} not running. Spawning...")
    #     pid = device.spawn([package_name])
    #     device.resume(pid)

    # session = device.attach(pid)
    # with open(script_path, "r") as f:
    #     script_source = f.read()
    # script = session.create_script(script_source)
    # script.on("message", on_message)
    # script.load()
    # session_store[app_alias] = session
    # logger.info(f"[FRIDA] Script loaded for {package_name} from {script_path}.")

def attach_via_gadget(package_name, script_path, session_store, alias, attach_timeout=30):
    """
    Attach to a running app (with Frida-Gadget preloaded) by polling
    until the process shows up, then load your Frida script.
    """
    device = frida.get_usb_device(timeout=5)
    deadline = time.monotonic() + attach_timeout
    pid = None

    # 1) Poll until the process exists (or timeout)
    while time.monotonic() < deadline:
        try:
            proc = device.get_process(package_name)
            pid = proc.pid
            break
        except frida.ProcessNotFoundError:
            logger.debug(f"[FRIDA] {package_name} not yet running; retrying in 1s…")
            time.sleep(1)

    if pid is None:
        logger.error(f"[FRIDA] Failed to find process '{package_name}' after {attach_timeout}s. Skipping attach.")
        return

    # 2) Attach and load the script
    session = device.attach(pid)
    with open(script_path, "r") as f:
        source = f.read()

    script = session.create_script(source)
    script.on("message", on_message)
    script.load()

    session_store[alias] = session
    logger.info(f"[FRIDA GADGET] Attached to {package_name} (pid={pid}) and loaded '{alias}'.")


def scrape_with_frida(platform_info, session_store, frequency):
    """
    Attach to the app via Frida-Gadget and then wait (up to a limit)
    for the next telemetry update, polling last_capture_time.
    """
    pkg    = platform_info["package"]
    alias  = platform_info["alias"]
    name   = platform_info["name"]
    script = platform_info["script"]

    # 1) Record the timestamp before attaching
    before_ts = last_capture_time.get(name, 0)

    # 2) Attach and inject your scrape script
    attach_via_gadget(pkg, script, session_store, alias)

    # 3) Poll for new telemetry until timeout = frequency * 0.3
    timeout   = frequency * 0.3
    deadline  = time.monotonic() + timeout
    logger.info(f"[HOST] Waiting up to {timeout:.1f}s for {name} telemetry…")

    while time.monotonic() < deadline:
        # If last_capture_time has moved past before_ts, we got data
        if last_capture_time.get(name, 0) > before_ts:
            elapsed = time.monotonic() - before_ts
            logger.info(f"[HOST] Received {name} telemetry after {elapsed:.1f}s")
            break
        time.sleep(0.5)
    else:
        # timeout expired
        logger.warning(
            "[HOST] No %s telemetry within %.1f seconds (proceeding)",
            name, timeout
        )


def cycle_apps(frequency=300):
    platforms = [
        { "name":"PlayStation", "package":"com.scee.psxandroid",
          "alias":"PS App", "activity":"com.scee.psxandroid.activity.TopActivity",
          "script":"scrape_playstation.js" },
        { "name":"Xbox",       "package":"com.microsoft.xboxone.smartglass",
          "alias":"Xbox",    "activity":"com.microsoft.xbox.MainActivity",
          "script":"scrape_xbox.js" },
    ]

    global session_store
    try:
        session_store
    except NameError:
        session_store = {}

    for plat in platforms:
        ensure_app_running(plat)

        # swipe if needed (using has_been_foregrounded & last_capture_time)…
        swipe_if_stale(plat["name"])

        # now attach & scrape
        scrape_with_frida(plat, session_store, frequency)


def run_cycle():
    try:
        cycle_apps(frequency)
    except Exception as e:
        logger.info("[HOST] Error in cycle_apps:", e)

if __name__ == "__main__":
    # 1) Start the daily digest scheduler
    logger.info("Starting digest scheduler (%d-hour interval)…", digest_interval_hours)
    schedule_digest(first_digest_time)

    # 2) Push the gadget and enable the LD_PRELOAD wrap
    push_gadget()

    # 3) Reboot once (so the gadget is preloaded by zygote)
    reboot_device(force=False)

    logger.info("[HOST] Entering telemetry collection loop…")
    while True:
        if reboot_event.is_set():
            time.sleep(30)
            continue

        # 4) Run one full scrape cycle (UI prep + Frida attach)
        run_cycle()

        # 5) Sleep until the next aligned interval
        now = time.monotonic()
        sleep_time = frequency - (now % frequency)
        logger.info(f"[HOST] Cycle complete. Sleeping {sleep_time:.0f}s until next run…")
        time.sleep(sleep_time)
