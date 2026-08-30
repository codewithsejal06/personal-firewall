from app.monitor.security_insights import generate_security_insights


def test_generate_security_insights():

    connections = [
        {
            "remote_address": "192.168.1.10:443",
            "firewall_decision": "ALLOW",
            "threat_detected": False,
        },
        {
            "remote_address": "192.168.1.20:443",
            "firewall_decision": "BLOCK",
            "threat_detected": True,
        },
        {
            "remote_address": "192.168.1.10:443",
            "firewall_decision": "ALLOW",
            "threat_detected": False,
        },
    ]

    insights = generate_security_insights(connections)

    assert insights["total_connections"] == 3
    assert insights["unique_connections"] == 2
    assert insights["repeated_connections"] == 1
    assert insights["blocked_connections"] == 1
    assert insights["threats_detected"] == 1
    assert insights["most_frequent_address"] == "192.168.1.10:443"


def test_security_insights_with_no_connections():

    insights = generate_security_insights([])

    assert insights["total_connections"] == 0
    assert insights["unique_connections"] == 0
    assert insights["repeated_connections"] == 0
    assert insights["blocked_connections"] == 0
    assert insights["threats_detected"] == 0
    assert insights["most_frequent_address"] is None