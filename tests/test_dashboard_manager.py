from app.dashboard.dashboard_manager import run_security_dashboard


def test_security_dashboard_workflow():
    """The complete dashboard workflow should return statistics."""

    connections = [
        {
            "firewall_decision": "ALLOW",
            "threat_detected": False,
            "severity": "LOW"
        },
        {
            "firewall_decision": "BLOCK",
            "threat_detected": True,
            "severity": "HIGH",
            "security_alert": {
                "alert_id": "ALERT-001",
                "severity": "HIGH",
                "classification": "SUSPICIOUS",
                "remote_address": "8.8.8.8",
                "status": "INVESTIGATING",
                "message": "Potential security threat detected."
            }
        }
    ]

    statistics = run_security_dashboard(connections)

    assert statistics["total_connections"] == 2
    assert statistics["blocked_connections"] == 1
    assert statistics["threats_detected"] == 1
    assert statistics["high_severity"] == 1