from app.response.incident_responder import respond_to_incident


def test_high_severity_incident_response():
    """High-severity alerts should receive a BLOCK response."""

    alert = {
        "alert_id": "ALERT-001",
        "severity": "HIGH",
        "status": "OPEN",
    }

    response = respond_to_incident(alert)

    assert response["action"] == "BLOCK"
    assert response["status"] == "INVESTIGATING"


def test_medium_severity_incident_response():
    """Medium-severity alerts should receive a MONITOR response."""

    alert = {
        "alert_id": "ALERT-002",
        "severity": "MEDIUM",
        "status": "OPEN",
    }

    response = respond_to_incident(alert)

    assert response["action"] == "MONITOR"
    assert response["status"] == "INVESTIGATING"


def test_low_severity_incident_response():
    """Low-severity alerts should be logged."""

    alert = {
        "alert_id": "ALERT-003",
        "severity": "LOW",
        "status": "OPEN",
    }

    response = respond_to_incident(alert)

    assert response["action"] == "LOG"
    assert response["status"] == "OPEN"