from app.alerts.alert_manager import create_alert
from app.detection.threat_detector import detect_threat


def test_threat_creates_security_alert():
    """A detected threat should generate a security alert."""

    connection = {
        "protocol": "TCP",
        "local_address": "192.168.1.10:50000",
        "remote_address": "8.8.8.8:443",
        "firewall_decision": "BLOCK",
        "classification": "EXTERNAL - ACTIVE"
    }

    # Detect threat
    threat_result = detect_threat(connection)

    connection["threat_detected"] = threat_result["threat_detected"]
    connection["severity"] = threat_result["severity"]
    connection["alerts"] = threat_result["alerts"]

    # Generate alert only when a threat exists
    if connection["threat_detected"]:
        connection["security_alert"] = create_alert(connection)
    else:
        connection["security_alert"] = None

    assert connection["threat_detected"] is True
    assert connection["security_alert"] is not None
    assert connection["security_alert"]["status"] == "OPEN"
    assert connection["security_alert"]["severity"] == "HIGH"