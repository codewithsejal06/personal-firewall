import json
from pathlib import Path
from datetime import datetime


DATA_FILE = Path("data/security_events.json")


def save_security_event(event):
    """
    Save a security event to the JSON event history.
    """

    DATA_FILE.parent.mkdir(parents=True, exist_ok=True)

    events = []

    if DATA_FILE.exists():
        try:
            with open(DATA_FILE, "r", encoding="utf-8") as file:
                events = json.load(file)
        except json.JSONDecodeError:
            events = []

    event["timestamp"] = datetime.now().isoformat(
        timespec="seconds"
    )

    events.append(event)

    with open(DATA_FILE, "w", encoding="utf-8") as file:
        json.dump(events, file, indent=4)

    return event


def load_security_events():
    """
    Load all saved security events.
    """

    if not DATA_FILE.exists():
        return []

    try:
        with open(DATA_FILE, "r", encoding="utf-8") as file:
            return json.load(file)
    except json.JSONDecodeError:
        return []
def filter_security_events(severity=None):
    """
    Load security events and optionally filter them by severity.
    """

    events = load_security_events()

    if severity is None:
        return events

    severity = severity.upper()

    filtered_events = [
        event for event in events
        if event.get("severity", "").upper() == severity
    ]

    return filtered_events