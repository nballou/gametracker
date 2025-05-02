import frida
import subprocess
import time
from datetime import datetime, timedelta
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

with open("credentials.json", "r") as cred_file:
    creds = json.load(cred_file)
yag = yagmail.SMTP(creds["email_address"], password=creds["password"])

# Directory to save CSV files locally (adjust as needed)
data_dir = "data"
if not os.path.exists(data_dir):
    os.makedirs(data_dir)

frequency = 180 # how often, in seconds, to cycle between apps
digest_interval_hours = 12 # how often to send the daily digest email

last_status = {} # initialize the last_status dictionary

# Alert check settings.
alert_check_interval = 60 # seconds between each check.
reopen_timeout = 2 * frequency + alert_check_interval  # seconds before restarting the app if telemetry is not received.
reboot_timeout = 3 * frequency + alert_check_interval  # seconds before rebooting the device if telemetry is still not received.
recovery_timeout = 4 * frequency + alert_check_interval   # seconds to wait *after* a reboot before sending a failure alert.
reboot_event = threading.Event()

state_lock = threading.Lock()

# Global variables to track the number of restarts and reboots.
restart_count = 0
reboot_count  = 0

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

# Escalation state for each platform: 0 = no escalation; 1 = app restarted; 2 = device rebooted.
escalation_state = {
    "PlayStation": 0,
    "Xbox": 0
}

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

def schedule_digest():
    """
    Schedule the next digest to run after `digest_interval_hours`.
    """
    delay = digest_interval_hours * 3600
    logger.debug("Scheduling next digest in %d seconds", delay)
    threading.Timer(delay, _digest_runner).start()

def _digest_runner():
    logger.debug("_digest_runner invoked")
    send_daily_digest()
    schedule_digest()

def reboot_device(force = False):

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

    """Reboot the device using ADB."""
    logger.info("[ADB] Rebooting device...")
    reboot_event.set()
    subprocess.run(["adb", "reboot"])
    time.sleep(40)  # wait for the device to finish rebooting
    subprocess.run(["adb", "root"])
    logger.info("[ADB] Waiting for device to come back online...")
    subprocess.run(["adb", "wait-for-device"])
    reboot_event.clear()
    time.sleep(30)  # wait for the device to finish rebooting
    logger.info("[ADB] Device reboot completed and event cleared.")
    reboot_frida()

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
                logger.info("No telemetry from %s for %d seconds; restarting app.", platform, reopen_timeout)
                # Optional alert before restart:
                # send_alert_email(
                #     subject=f"Telemetry Alert - {platform} - App Restart",
                #     body=f"No telemetry received from {platform} in the expected timeframe. Action taken: App Restart."
                # )
                pkg = {"PlayStation": "com.scee.psxandroid", "Xbox": "com.microsoft.xboxone.smartglass"}[platform]
                close_app(pkg)
                time.sleep(1)
                launch_app(pkg)
                # Record that we’ve done one restart
                with state_lock:
                    escalation_state[platform] = 1

            # 2) Already restarted once → reboot device if still no telemetry by reboot_timeout
            elif state == 1 and elapsed > reboot_timeout:
                logger.info("Still no telemetry from %s after app restart; rebooting device.", platform)
                # Optional alert before reboot:
                # send_alert_email(
                #     subject=f"Telemetry Alert - {platform} - Device Reboot",
                #     body=f"Still no telemetry received from {platform} after restart. Action taken: Device Rebooted."
                # )
                reboot_device(force=True)
                # Record that we’ve done the reboot
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

def kill_frida_server():
    try:
        subprocess.run(["adb", "shell", "pkill", "frida-server"], check=True)
    except subprocess.CalledProcessError as e:
        try:
            subprocess.run(["adb", "shell", "killall", "frida-server"], check=True)
            # logger.debug("Successfully ran killall frida-server.")
        except subprocess.CalledProcessError as e:
            pass
    time.sleep(1)

def start_frida_server():
    """
    Start Frida-server on the AVD.
    This assumes that the frida-server binary is already on the device
    at /data/local/tmp/ and has executable permissions.
    """
    logger.info("[HOST] Starting frida-server on device...")
    # Use adb shell with su to start frida-server in the background.
    command = "adb shell nohup /data/local/tmp/frida-server > /dev/null 2>&1 &"
    subprocess.run(command, shell=True)
    time.sleep(3)

def reboot_frida():
    """
    Reboot the frida-server on the device.
    This is useful if the server has crashed or is unresponsive.
    """
    # logger.info("[HOST] Rebooting frida-server...")
    kill_frida_server()
    start_frida_server()

def run_cycle():
    try:
        cycle_apps(frequency)
    except Exception as e:
        logger.info("[HOST] Error in cycle_apps:", e)

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

def launch_app(package):
    """Launch an Android app via ADB using monkey command."""
    logger.info(f"[ADB] Launching {package} using monkey command")
    subprocess.run(
        ["adb", "shell", "monkey", "-p", package, "-c", "android.intent.category.LAUNCHER", "1"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    time.sleep(5)
    open_friends_tab(package)

def close_app(package):
    """Close the app using ADB."""
    logger.info(f"[ADB] Closing {package}...")
    subprocess.run(
        ["adb", "shell", "am", "force-stop", package],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    time.sleep(5)

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

def swipe_down():
    """Perform a vertical swipe from a random position within the specified rectangle."""
    start_x = random.randint(150, 900)
    start_y = random.randint(600, 950)
    end_y = random.randint(1800, 2000)  # Ensure the swipe ends no lower than Y = 1800
    # logger.info(f"[ADB] Swiping from ({start_x}, {start_y}) to ({start_x}, {end_y})")
    subprocess.run(["adb", "shell", "input", "swipe", str(start_x), str(start_y), str(start_x), str(end_y)])

def is_app_running(device, app_alias):
    """Check if the app process is already running."""
    processes = device.enumerate_processes()  # Note: using snake_case method
    for proc in processes:
        if proc.name == app_alias:
            return True
    return False

def attach_frida_to_app(package_name, app_alias, activity, script_path, session_store):
    """Attach Frida to the app process (spawn if needed) and load the provided script."""
    device = frida.get_usb_device(timeout=5)
    running = is_app_running(device, app_alias)
    
    if running:
        try:
            process = device.get_process(app_alias)
            pid = process.pid
            # logger.info(f"[FRIDA] {app_alias} already running with pid {pid}. Switching to foreground...")
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                bring_to_foreground(package_name, activity)
            time.sleep(5)  # Allow some time for the app to come to the foreground.
            swipe_down()
        except frida.ProcessNotFoundError as e:
            logger.info(f"[FRIDA] Process not found: {e}")
            # Process might have disappeared; spawn if necessary.
            running = False

    if not running:
        logger.info(f"[FRIDA] {package_name} not running. Spawning...")
        pid = device.spawn([package_name])
        device.resume(pid)
        time.sleep(5) # Allow some time for the app to start.
        # logger.info(f"[FRIDA] Spawned {package_name} with pid {pid}.")

    session = device.attach(pid)
    with open(script_path, "r") as f:
        script_source = f.read()
    script = session.create_script(script_source)
    script.on("message", on_message)
    script.load()
    session_store[app_alias] = session
    # logger.info(f"[FRIDA] Script loaded for {package_name} from {script_path}.")

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

def cycle_apps(frequency = 300):
    """Cycle between launching PlayStation and Xbox apps, attach Frida scripts, and collect CSV data."""
    # Define package names and main activities.
    ps_package = "com.scee.psxandroid"
    ps_alias = "PS App"
    ps_activity = "com.scee.psxandroid.activity.TopActivity"

    xbox_package = "com.microsoft.xboxone.smartglass"
    xbox_alias = "Xbox"
    xbox_activity = "com.microsoft.xbox.MainActivity"
    
    # A dictionary to hold Frida sessions.
    session_store = {}
    
    # ----- Process for PlayStation app -----
    attach_frida_to_app(ps_package, ps_alias, ps_activity, "scrape_playstation.js", session_store)
    logger.info("[HOST] Waiting for PlayStation telemetry...")
    time.sleep(frequency * .3)

    # ----- Process for Xbox app -----
    attach_frida_to_app(xbox_package, xbox_alias, xbox_activity, "scrape_xbox.js", session_store)
    logger.info("[HOST] Waiting for Xbox telemetry...")
    time.sleep(frequency * .3)

if __name__ == "__main__":

    # Start the recurring digest cycle
    logger.info("Starting digest scheduler with interval %d hours", digest_interval_hours)
    schedule_digest()

    reboot_device(force = False)
    reboot_frida()
    # Check if adb is already in root mode

    logger.info("[HOST] Starting telemetry collection workflow...")
    while True:

        # If a reboot is in progress, wait until it's done.
        if reboot_event.is_set():
            logger.info("Device is rebooting. Pausing cycle_apps until reboot is complete...")
            time.sleep(30)  # adjust the sleep duration as appropriate
            continue  # Skip this iteration of the loop until reboot_event is cleared.

        start_time = time.monotonic()
        run_cycle()
        now = time.monotonic()
        remainder = now % frequency  # Calculate time passed since the epoch remainder with respect to frequency
        sleep_time = frequency - remainder
        logger.info(f"[HOST] Cycle complete. Waiting {sleep_time:.0f} seconds until next cycle...")
        time.sleep(sleep_time)
