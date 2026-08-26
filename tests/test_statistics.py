from app.dashboard.statistics import calculate_security_statistics


def test_security_statistics():

    connections = [
        {
            "firewall_decision": "ALLOW",
            "threat_detected": False,
            "severity": "LOW"
        },
        {
            "firewall_decision": "BLOCK",
            "threat_detected": True,
            "severity": "HIGH"
        },
        {
            "firewall_decision": "BLOCK",
            "threat_detected": True,
            "severity": "MEDIUM"
        }
    ]

    result = calculate_security_statistics(connections)

    assert result["total_connections"] == 3
    assert result["allowed_connections"] == 1
    assert result["blocked_connections"] == 2
    assert result["threats_detected"] == 2
    assert result["high_severity"] == 1
    assert result["medium_severity"] == 1
    assert result["low_severity"] == 1