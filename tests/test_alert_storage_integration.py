from app.alerts.alert_manager import create_alert
from app.storage.event_storage import load_security_events


def test_alert_is_automatically_saved():

    connection = {
        "remote_address": "192.168.1.200:443",
        "severity": "HIGH",
        "classification": "SUSPICIOUS"
    }

    alert = create_alert(connection)

    events = load_security_events()

    assert alert["severity"] == "HIGH"
    assert "timestamp" in alert
    assert any(
        event.get("alert_id") == alert.get("alert_id")
        for event in events
    )