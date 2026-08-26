from app.alerts.alert_manager import create_alert


def test_create_alert():
    connection = {
        "severity": "HIGH",
        "classification": "EXTERNAL - ACTIVE",
        "remote_address": "203.0.113.10:443"
    }

    alert = create_alert(connection)

    assert alert["severity"] == "HIGH"
    assert alert["status"] == "OPEN"
    assert alert["alert_id"].startswith("ALERT-")