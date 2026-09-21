from app.response.incident_responder import respond_to_incident

from app.storage.incident_storage import (
    save_incidents,
    load_incidents,
    clear_stored_incidents,
)

from datetime import datetime


# Load previously stored incidents.
loaded_incidents = load_incidents()

INCIDENTS = {
    incident["incident_id"]: incident
    for incident in loaded_incidents
}


def create_incident(connection):
    """
    Create a new security incident.

    If an active incident already exists for the same
    remote address, return the existing incident.
    """

    remote_address = connection.get(
        "remote_address",
        "N/A"
    )

    # Check for duplicate active incidents.
    for incident in INCIDENTS.values():
        if (
            incident["remote_address"] == remote_address
            and incident["status"] != "RESOLVED"
        ):
            return incident

    # Generate a new incident ID.
    incident_id = f"INC-{len(INCIDENTS) + 1:04d}"

    incident = {
        "incident_id": incident_id,
        "status": "OPEN",
        "severity": connection.get(
            "severity",
            "LOW"
        ),
        "remote_address": remote_address,
        "created_at": datetime.now().isoformat(
            timespec="seconds"
        ),
        "connection": connection.copy(),
    }

    # -----------------------------------
    # Automatic Incident Response
    # -----------------------------------

    response = respond_to_incident(incident)

    incident["response"] = response

    # Update incident status based on automatic response.
    incident["status"] = response["status"]

    # -----------------------------------
    # Sprint 16.3
    # Incident Response History
    # -----------------------------------

    incident["response_history"] = [
        {
            "action": response["action"],
            "status": response["status"],
            "timestamp": datetime.now().isoformat(
                timespec="seconds"
            ),
        }
    ]

    # Store incident in memory.
    INCIDENTS[incident_id] = incident

    # Save incident to persistent storage.
    save_incidents(
        list(INCIDENTS.values())
    )

    return incident


def get_incident(incident_id):
    """
    Return an incident using its incident ID.
    """

    return INCIDENTS.get(incident_id)


def get_all_incidents():
    """
    Return all stored incidents.
    """

    return list(INCIDENTS.values())


def get_incident_history(incident_id):
    """
    Return the response history of an incident.

    Returns:
        list: Response history entries.
        None: If the incident does not exist.
    """

    incident = INCIDENTS.get(incident_id)

    if incident is None:
        return None

    return incident.get(
        "response_history",
        []
    )


def get_incident_timeline(incident_id):
    """
    Return a complete timeline of an incident.

    The timeline is built from the incident's
    response history.
    """

    incident = INCIDENTS.get(incident_id)

    if incident is None:
        return None

    timeline = []

    # Incident creation event
    timeline.append({
        "event": "INCIDENT_CREATED",
        "status": incident.get(
            "status",
            "OPEN"
        ),
        "timestamp": incident.get(
            "created_at",
            "N/A"
        ),
    })

    # Add response history
    for history_item in incident.get(
        "response_history",
        []
    ):
        timeline.append({
            "event": history_item.get(
                "action",
                "UNKNOWN"
            ),
            "status": history_item.get(
                "status",
                "UNKNOWN"
            ),
            "timestamp": history_item.get(
                "timestamp",
                "N/A"
            ),
        })

    return timeline


def update_incident_status(
    incident_id,
    new_status
):
    """
    Update the status of an existing security incident.

    Every status change is added to the incident's
    response history.
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

    incident = INCIDENTS.get(
        incident_id
    )

    if incident is None:
        return None

    # Update incident status.
    incident["status"] = new_status

    # -----------------------------------
    # Sprint 16.3
    # Add status update to history
    # -----------------------------------

    incident.setdefault(
        "response_history",
        []
    ).append(
        {
            "action": "STATUS_UPDATE",
            "status": new_status,
            "timestamp": datetime.now().isoformat(
                timespec="seconds"
            ),
        }
    )

    # Save updated incident.
    save_incidents(
        list(INCIDENTS.values())
    )

    return incident


def clear_incidents():
    """
    Clear all incidents from memory
    and persistent storage.
    """

    INCIDENTS.clear()

    clear_stored_incidents()


def get_incident_summary():
    """
    Generate a summary of all incidents.
    """

    summary = {
        "total_incidents": len(
            INCIDENTS
        ),
        "open_incidents": 0,
        "resolved_incidents": 0,
        "high_severity": 0,
        "medium_severity": 0,
        "low_severity": 0,
    }

    for incident in INCIDENTS.values():

        status = incident.get(
            "status",
            "OPEN"
        )

        severity = incident.get(
            "severity",
            "LOW"
        )

        if status == "RESOLVED":
            summary[
                "resolved_incidents"
            ] += 1
        else:
            summary[
                "open_incidents"
            ] += 1

        if severity == "HIGH":
            summary[
                "high_severity"
            ] += 1

        elif severity == "MEDIUM":
            summary[
                "medium_severity"
            ] += 1

        elif severity == "LOW":
            summary[
                "low_severity"
            ] += 1

    return summary


def reload_incidents():
    """
    Reload incidents from persistent storage.

    This simulates loading incident data
    after an application restart.
    """

    stored_incidents = load_incidents()

    INCIDENTS.clear()

    for incident in stored_incidents:

        incident_id = incident["incident_id"]

        # Backward compatibility:
        # Older incidents may not have response_history.
        incident.setdefault(
            "response_history",
            []
        )

        INCIDENTS[incident_id] = incident

    return get_all_incidents()