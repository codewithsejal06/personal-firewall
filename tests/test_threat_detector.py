from app.detection.threat_detector import detect_threat


def test_normal_connection():
    """Normal connections should not be detected as threats."""

    connection = {
        "protocol": "TCP",
        "local_address": "192.168.1.10:50000",
        "remote_address": "8.8.8.8:443",
        "firewall_decision": "ALLOW",
    }

    result = detect_threat(connection)

    assert result["threat_detected"] is False
    assert result["severity"] == "LOW"
    assert result["alerts"] == []


def test_suspicious_ip():
    """Connections matching the suspicious IP list should be detected."""

    connection = {
        "protocol": "TCP",
        "local_address": "192.168.1.10:50000",
        "remote_address": "198.51.100.50:443",
        "firewall_decision": "ALLOW",
    }

    result = detect_threat(connection)

    assert result["threat_detected"] is True
    assert result["severity"] == "MEDIUM"
    assert len(result["alerts"]) == 1


def test_blocked_connection():
    """Firewall-blocked connections should receive HIGH severity."""

    connection = {
        "protocol": "TCP",
        "local_address": "192.168.1.10:50000",
        "remote_address": "8.8.8.8:443",
        "firewall_decision": "BLOCK",
    }

    result = detect_threat(connection)

    assert result["threat_detected"] is True
    assert result["severity"] == "HIGH"