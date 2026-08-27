from app.storage.event_viewer import format_security_event


def test_format_security_event():

    event = {
        "alert_id": "ALERT-001",
        "timestamp": "2026-08-27T12:00:00",
        "severity": "HIGH",
        "classification": "SUSPICIOUS",
        "remote_address": "192.168.1.100:443",
        "status": "OPEN",
        "message": "Potential security threat detected."
    }

    formatted_event = format_security_event(event)

    assert "ALERT-001" in formatted_event
    assert "HIGH" in formatted_event
    assert "192.168.1.100:443" in formatted_event
    assert "Potential security threat detected." in formatted_event