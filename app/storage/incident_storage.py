import json
from pathlib import Path


INCIDENT_DATA_FILE = Path("data/incidents.json")


def save_incidents(incidents):
    """
    Save all incidents to persistent JSON storage.
    """

    INCIDENT_DATA_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with open(
        INCIDENT_DATA_FILE,
        "w",
        encoding="utf-8"
    ) as file:
        json.dump(
            incidents,
            file,
            indent=4
        )


def load_incidents():
    """
    Load incidents from persistent JSON storage.
    """

    if not INCIDENT_DATA_FILE.exists():
        return []

    try:
        with open(
            INCIDENT_DATA_FILE,
            "r",
            encoding="utf-8"
        ) as file:
            incidents = json.load(file)

        return incidents

    except json.JSONDecodeError:
        return []


def clear_stored_incidents():
    """
    Clear all persisted incidents.
    """

    if INCIDENT_DATA_FILE.exists():
        INCIDENT_DATA_FILE.unlink()