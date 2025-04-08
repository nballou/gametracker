import frida
import subprocess
import time
import datetime
import sys
import csv
import os
import io
import pandas as pd
import random
import logging
from logging.handlers import TimedRotatingFileHandler
import datetime

# Directory to save CSV files locally (adjust as needed)
CSV_SAVE_DIR = "data"
if not os.path.exists(CSV_SAVE_DIR):
    os.makedirs(CSV_SAVE_DIR)

frequency = 120 # how often, in seconds, to cycle between apps

last_status = {} # initialize the last_status dictionary


# Create a logger object
logger = logging.getLogger("orchestrator")
logger.setLevel(logging.DEBUG)

# Create a handler that writes log messages to a file.
# This handler will rotate the log file at midnight.
log_filename = "log.log"  # base filename
handler = TimedRotatingFileHandler(log_filename, when="midnight", backupCount=7)
# Optionally, if you want the filename to include the date, you can use the suffix.
handler.suffix = "%Y-%m-%d"
handler.setLevel(logging.DEBUG)

# Set a simple log message format
formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s')
handler.setFormatter(formatter)

# Add the handler to your logger
logger.addHandler(handler)

# (Optional) Also output logs to the console.
consoleHandler = logging.StreamHandler()
consoleHandler.setFormatter(formatter)
consoleHandler.setLevel(logging.DEBUG)
logger.addHandler(consoleHandler)

def kill_frida_server():
    logger.info("[HOST] Killing any running frida-server instance...")
    # Try pkill first.
    try:
        subprocess.run(["adb", "shell", "pkill", "frida-server"], check=True)
        # logger.debug("Successfully ran pkill frida-server.")
    except subprocess.CalledProcessError as e:
        pass
        # logger.debug(f"pkill did not terminate any processes (or error occurred): {e}")
    
    # Then try killall.
    try:
        subprocess.run(["adb", "shell", "killall", "frida-server"], check=True)
        # logger.debug("Successfully ran killall frida-server.")
    except subprocess.CalledProcessError as e:
        pass
        # logger.debug(f"killall did not terminate any processes (or error occurred): {e}")
    
    # Give it a moment to ensure termination.
    time.sleep(1)
    # logger.info("[HOST] frida-server should now be terminated (if it was running).")


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
    time.sleep(2)
    logger.info("[HOST] frida-server should now be running.")

def run_cycle():
    try:
        cycle_apps(frequency)
    except Exception as e:
        logger.info("[HOST] Error in cycle_apps:", e)

def get_daily_filename():
    """Return the CSV filename for the current day."""
    date_str = datetime.datetime.now().strftime("%Y-%m-%d")
    return f"{CSV_SAVE_DIR}/telemetry_{date_str}.csv"

def load_existing_data():
    """Load the daily CSV file (if exists) to populate the last_status dictionary."""
    filename = get_daily_filename()
    if os.path.exists(filename):
        with open(filename, "r", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                # Use xuid if available; otherwise fall back to gamertag.
                unique_id = row.get("accountID")
                key = (row.get("platform", ""), unique_id)
                # We'll track presenceState as the status we care about.
                last_status[key] = row.get("presenceState", "")
        logger.info(f"[HOST] Loaded previous status data from {filename}")
    else:
        logger.info(f"[HOST] No existing data for today ({filename}). Starting fresh.")

def process_csv_data(csv_str, platform):
    """
    Process CSV data received from Frida for a given platform.
    Only add new rows if the person's presenceState has changed.
    Also add a checkTimestamp and platform column.
    """
    global last_status
    new_rows = []
    now = datetime.datetime.now().isoformat()
    f = io.StringIO(csv_str)
    reader = csv.DictReader(f)
    debug_count = 0
    for row in reader:
        unique_id = row.get("accountID")  # unique identifier for the user
        if not unique_id:
            logger.debug("Skipping row with empty unique_id: %s", row)
            continue
        key = (platform, unique_id)
        new_status = row.get("presenceState", "")
        old_status = last_status.get(key)
        if key not in last_status or old_status != new_status:
            last_status[key] = new_status
            row["time"] = now
            new_rows.append(row)
            debug_count += 1
            logger.debug("Change detected for key %s: old_status=%r, new_status=%r", key, old_status, new_status)
    logger.debug("process_csv_data: %d new row(s) detected from platform %s.", debug_count, platform)
    if new_rows:
        update_person_csv(new_rows)
    else:
        logger.info("[HOST] No status changes detected; nothing appended.")

def update_daily_csv(new_rows):
    """Append new rows to today's CSV file."""
    filename = get_daily_filename()
    file_exists = os.path.exists(filename)
    # Define fieldnames that match your CSV column names.
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
    try:
        with open(filename, "a", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            if not file_exists:
                writer.writeheader()
                logger.debug(f"update_daily_csv: Creating new file and writing header to {filename}.")
            for row in new_rows:
                # To ensure we write only the expected keys, filter the row.
                filtered = {key: row.get(key, "") for key in fieldnames}
                writer.writerow(filtered)
            logger.info(f"update_daily_csv: Appended {len(new_rows)} row(s) to {filename}.")
    except Exception as e:
        logger.info(f"[HOST] Error saving CSV: {e}")


# Load today's CSV (if exists) on startup.
load_existing_data()

def launch_app(package):
    """Launch an Android app via ADB using monkey command."""
    logger.info(f"[ADB] Launching {package} using monkey command")
    subprocess.run(["adb", "shell", "monkey", "-p", package, "-c", "android.intent.category.LAUNCHER", "1"])

    if package == "com.scee.psxandroid":
        time.sleep(5)
        subprocess.run(["adb", "shell", "input", "tap", "955", "200"]) # open friends tab
        time.sleep(5)

    if package == "com.microsoft.xboxone.smartglass":
        time.sleep(5)
        subprocess.run(["adb", "shell", "input", "tap", "320", "2190"]) # open friends tab
        time.sleep(5)

def bring_to_foreground(package, activity):
    """Bring the app to the foreground using ADB."""
    logger.info(f"[ADB] Bringing {package}/{activity} to foreground")
    subprocess.run(["adb", "shell", "am", "start", "-n", f"{package}/{activity}"])

def swipe_down():
    """Perform a vertical swipe from a random position within the specified rectangle."""
    start_x = random.randint(150, 900)
    start_y = random.randint(600, 950)
    end_y = random.randint(1800, 2000)  # Ensure the swipe ends no lower than Y = 1800
    logger.info(f"[ADB] Swiping from ({start_x}, {start_y}) to ({start_x}, {end_y})")
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
            logger.info(f"[FRIDA] {app_alias} already running with pid {pid}. Switching to foreground...")
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
        logger.info(f"[FRIDA] Spawned {package_name} with pid {pid}.")

    session = device.attach(pid)
    with open(script_path, "r") as f:
        script_source = f.read()
    script = session.create_script(script_source)
    script.on("message", on_message)
    script.load()
    session_store[app_alias] = session
    logger.info(f"[FRIDA] Script loaded for {package_name} from {script_path}.")

def on_message(message, data):
    """Handle messages sent from the Frida script."""
    if message["type"] == "send":
        payload = message["payload"]
        if payload.get("type") == "csv-data":
            # Retrieve CSV data from the payload.
            csv_data = payload.get("csv", "")
            platform = payload.get("platform", "")
            if csv_data:
                logger.info(f"[HOST] Received CSV data from {platform}")
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

    kill_frida_server()
    # Check if adb is already in root mode
    result = subprocess.run(["adb", "shell", "whoami"], capture_output=True, text=True)
    if "root" in result.stdout.strip():
        logger.info("[HOST] Device is already in root mode. Proceeding...")
    else:
        logger.info("[HOST] Device is not in root mode. Rebooting into root mode...")
        subprocess.run(["adb", "reboot"])
        logger.info("[HOST] Rebooting device...")
        time.sleep(20)  # wait for the device to finish rebooting
        subprocess.run(["adb", "root"])
        time.sleep(5)  # wait for the device to finish rebooting
    
    # Start frida-server (necessary after a reboot).
    start_frida_server()

    # Continue with the rest of your orchestration...

    logger.info("[HOST] Starting telemetry collection workflow...")
    while True:
        start_time = time.time()
        run_cycle()
        now = time.time()
        # Calculate time passed since the epoch remainder with respect to frequency
        remainder = now % frequency
        sleep_time = frequency - remainder
        logger.info(f"[HOST] Cycle complete. Waiting {sleep_time:0f} seconds until next cycle...")
        time.sleep(sleep_time)
