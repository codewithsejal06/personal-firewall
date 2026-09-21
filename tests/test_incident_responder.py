from app.response.incident_responder import respond_to_incident


def test_high_severity_incident_response():
    """High-severity incidents should be blocked and investigated."""

    alert = {
        "alert_id": "ALERT-001",
        "severity": "HIGH",
        "status": "OPEN",
    }

    response = respond_to_incident(alert)

    assert response["action"] == "BLOCK_AND_INVESTIGATE"
    assert response["status"] == "INVESTIGATING"


def test_medium_severity_incident_response():
    """Medium-severity incidents should be investigated."""

    alert = {
        "alert_id": "ALERT-002",
        "severity": "MEDIUM",
        "status": "OPEN",
    }

    response = respond_to_incident(alert)

    assert response["action"] == "INVESTIGATE"
    assert response["status"] == "INVESTIGATING"


def test_low_severity_incident_response():
    """Low-severity incidents should be monitored."""

    alert = {
        "alert_id": "ALERT-003",
        "severity": "LOW",
        "status": "OPEN",
    }

    response = respond_to_incident(alert)

    assert response["action"] == "MONITOR"
    assert response["status"] == "OPEN"