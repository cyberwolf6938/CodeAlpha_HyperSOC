from datetime import datetime

LOG_FILE = "alerts.log"


def write_alert(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    line = f"[{timestamp}] {message}\n"

    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(line)