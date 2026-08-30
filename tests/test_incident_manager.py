from app.response.incident_manager import (
    create_incident,
    get_incident,
    get_all_incidents,
    clear_incidents,
    update_incident_status,
    get_incident_summary,
)


def setup_function():
    """
    Clear incidents before every test.
    """

    clear_incidents()


def test_create_incident():

    connection = {
        "remote_address": "203.0.113.10:443",
        "severity": "HIGH",
        "threat_detected": True,
    }

    incident = create_incident(connection)

    assert incident["incident_id"] == "INC-0001"
    assert incident["status"] == "OPEN"
    assert incident["severity"] == "HIGH"
    assert incident["remote_address"] == "203.0.113.10:443"


def test_get_incident():

    incident = create_incident({
        "remote_address": "198.51.100.20:443",
        "severity": "MEDIUM",
    })

    result = get_incident(incident["incident_id"])

    assert result == incident


def test_get_all_incidents():

    create_incident({
        "remote_address": "203.0.113.10:443",
        "severity": "HIGH",
    })

    create_incident({
        "remote_address": "198.51.100.20:80",
        "severity": "MEDIUM",
    })

    incidents = get_all_incidents()

    assert len(incidents) == 2


def test_clear_incidents():

    create_incident({
        "remote_address": "203.0.113.10:443",
        "severity": "HIGH",
    })

    clear_incidents()

    incidents = get_all_incidents()

    assert incidents == []


def test_update_incident_status():

    incident = create_incident({
        "remote_address": "203.0.113.10:443",
        "severity": "HIGH",
    })

    updated_incident = update_incident_status(
        incident["incident_id"],
        "INVESTIGATING",
    )

    assert updated_incident["status"] == "INVESTIGATING"


def test_resolve_incident():

    incident = create_incident({
        "remote_address": "198.51.100.20:80",
        "severity": "MEDIUM",
    })

    updated_incident = update_incident_status(
        incident["incident_id"],
        "RESOLVED",
    )

    assert updated_incident["status"] == "RESOLVED"


def test_update_invalid_incident_status():

    incident = create_incident({
        "remote_address": "203.0.113.10:443",
        "severity": "HIGH",
    })

    import pytest

    with pytest.raises(ValueError):
        update_incident_status(
            incident["incident_id"],
            "INVALID_STATUS",
        )


def test_update_nonexistent_incident():

    result = update_incident_status(
        "INC-9999",
        "RESOLVED",
    )

    assert result is None


def test_duplicate_incident_returns_existing_incident():

    connection = {
        "remote_address": "203.0.113.10:443",
        "severity": "HIGH",
    }

    first_incident = create_incident(connection)
    second_incident = create_incident(connection)

    assert first_incident["incident_id"] == second_incident["incident_id"]

    incidents = get_all_incidents()

    assert len(incidents) == 1


def test_resolved_incident_allows_new_incident():

    connection = {
        "remote_address": "203.0.113.10:443",
        "severity": "HIGH",
    }

    first_incident = create_incident(connection)

    update_incident_status(
        first_incident["incident_id"],
        "RESOLVED",
    )

    second_incident = create_incident(connection)

    assert first_incident["incident_id"] != second_incident["incident_id"]

    incidents = get_all_incidents()

    assert len(incidents) == 2


def test_incident_summary():

    create_incident({
        "remote_address": "203.0.113.10:443",
        "severity": "HIGH",
    })

    medium_incident = create_incident({
        "remote_address": "198.51.100.20:80",
        "severity": "MEDIUM",
    })

    create_incident({
        "remote_address": "192.0.2.30:22",
        "severity": "LOW",
    })

    update_incident_status(
        medium_incident["incident_id"],
        "RESOLVED",
    )

    summary = get_incident_summary()

    assert summary["total_incidents"] == 3
    assert summary["open_incidents"] == 2
    assert summary["resolved_incidents"] == 1
    assert summary["high_severity"] == 1
    assert summary["medium_severity"] == 1
    assert summary["low_severity"] == 1


def test_empty_incident_summary():

    summary = get_incident_summary()

    assert summary["total_incidents"] == 0
    assert summary["open_incidents"] == 0
    assert summary["resolved_incidents"] == 0