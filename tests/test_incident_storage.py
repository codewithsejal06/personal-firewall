from app.storage.incident_storage import (
    save_incidents,
    load_incidents,
    clear_stored_incidents,
)


def test_save_and_load_incidents():
    """
    Test saving and loading incidents.
    """

    clear_stored_incidents()

    incidents = [
        {
            "incident_id": 1,
            "severity": "HIGH",
            "status": "OPEN",
        },
        {
            "incident_id": 2,
            "severity": "MEDIUM",
            "status": "RESOLVED",
        },
    ]

    save_incidents(incidents)

    loaded_incidents = load_incidents()

    assert loaded_incidents == incidents

    clear_stored_incidents()


def test_load_incidents_when_file_does_not_exist():
    """
    Test loading incidents when no storage file exists.
    """

    clear_stored_incidents()

    incidents = load_incidents()

    assert incidents == []


from app.response.incident_manager import (
    create_incident,
    update_incident_status,
    clear_incidents,
)


def test_incident_status_persists_after_update():

    # Start with clean storage.
    clear_incidents()

    connection = {
        "remote_address": "203.0.113.100:443",
        "severity": "HIGH",
    }

    # Create incident.
    incident = create_incident(connection)

    # Update incident status.
    update_incident_status(
        incident["incident_id"],
        "RESOLVED"
    )

    # Reload incidents directly from storage.
    loaded_incidents = load_incidents()

    assert len(loaded_incidents) == 1

    assert (
        loaded_incidents[0]["status"]
        == "RESOLVED"
    )

    # Clean up after test.
    clear_incidents()



def test_updated_incident_status_is_saved_to_storage():

    clear_incidents()

    connection = {
        "remote_address": "203.0.113.150:443",
        "severity": "MEDIUM",
    }

    # Create a new incident.
    incident = create_incident(connection)

    # Update its status.
    updated_incident = update_incident_status(
        incident["incident_id"],
        "INVESTIGATING"
    )

    assert updated_incident["status"] == "INVESTIGATING"

    # Load incidents directly from persistent storage.
    stored_incidents = load_incidents()

    assert len(stored_incidents) == 1

    assert (
        stored_incidents[0]["incident_id"]
        == incident["incident_id"]
    )

    assert (
        stored_incidents[0]["status"]
        == "INVESTIGATING"
    )

    # Clean up.
    clear_incidents()