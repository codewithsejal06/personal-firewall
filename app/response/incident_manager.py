from datetime import datetime


# Stores incidents during the current application session.
INCIDENTS = {}


def create_incident(connection):
    """
    Create and store a security incident from a processed connection.
    """

    incident_id = f"INC-{len(INCIDENTS) + 1:04d}"

    incident = {
        "incident_id": incident_id,
        "status": "OPEN",
        "severity": connection.get("severity", "LOW"),
        "remote_address": connection.get("remote_address", "N/A"),
        "created_at": datetime.now().isoformat(timespec="seconds"),
        "connection": connection.copy(),
    }

    INCIDENTS[incident_id] = incident

    return incident


def get_incident(incident_id):
    """
    Return an incident using its incident ID.
    """

    return INCIDENTS.get(incident_id)


def get_all_incidents():
    """
    Return all incidents created during the current session.
    """

    return list(INCIDENTS.values())


def update_incident_status(incident_id, new_status):
    """
    Update the status of an existing security incident.
    """

    valid_statuses = {
        "OPEN",
        "INVESTIGATING",
        "RESOLVED",
    }

    new_status = new_status.upper()

    if new_status not in valid_statuses:
        raise ValueError(
            f"Invalid incident status: {new_status}"
        )

    incident = INCIDENTS.get(incident_id)

    if incident is None:
        return None

    incident["status"] = new_status

    return incident


def create_incident(connection):
    """
    Create and store a security incident from a processed connection.

    If an open incident already exists for the same remote address,
    return the existing incident instead of creating a duplicate.
    """

    remote_address = connection.get("remote_address", "N/A")

    for incident in INCIDENTS.values():
        if (
            incident["remote_address"] == remote_address
            and incident["status"] != "RESOLVED"
        ):
            return incident

    incident_id = f"INC-{len(INCIDENTS) + 1:04d}"

    incident = {
        "incident_id": incident_id,
        "status": "OPEN",
        "severity": connection.get("severity", "LOW"),
        "remote_address": remote_address,
        "created_at": datetime.now().isoformat(timespec="seconds"),
        "connection": connection.copy(),
    }

    INCIDENTS[incident_id] = incident

    return incident


def clear_incidents():
    """
    Clear all stored incidents.

    Useful for testing and starting a new security monitoring session.
    """

    INCIDENTS.clear()


def get_incident_summary():
    """
    Generate a summary of all incidents.
    """

    summary = {
        "total_incidents": len(INCIDENTS),
        "open_incidents": 0,
        "resolved_incidents": 0,
        "high_severity": 0,
        "medium_severity": 0,
        "low_severity": 0,
    }

    for incident in INCIDENTS.values():
        status = incident.get("status", "OPEN")
        severity = incident.get("severity", "LOW")

        if status == "RESOLVED":
            summary["resolved_incidents"] += 1
        else:
            summary["open_incidents"] += 1

        if severity == "HIGH":
            summary["high_severity"] += 1
        elif severity == "MEDIUM":
            summary["medium_severity"] += 1
        elif severity == "LOW":
            summary["low_severity"] += 1

    return summary