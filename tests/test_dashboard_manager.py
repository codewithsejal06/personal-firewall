from app.dashboard.dashboard_manager import (
    run_security_dashboard,
    display_security_insights,
    display_incident_summary,
)


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


def test_display_security_insights(capsys):

    insights = {
        "total_connections": 10,
        "unique_connections": 6,
        "repeated_connections": 4,
        "blocked_connections": 2,
        "threats_detected": 3,
        "most_frequent_address": "192.168.1.10:443",
    }

    display_security_insights(insights)

    captured = capsys.readouterr()

    assert "SECURITY INSIGHTS" in captured.out
    assert "Total Connections      : 10" in captured.out
    assert "Unique Connections     : 6" in captured.out
    assert "Repeated Connections   : 4" in captured.out
    assert "Blocked Connections    : 2" in captured.out
    assert "Threats Detected       : 3" in captured.out
    assert "192.168.1.10:443" in captured.out


def test_display_security_insights_with_no_connections(capsys):

    insights = {
        "total_connections": 0,
        "unique_connections": 0,
        "repeated_connections": 0,
        "blocked_connections": 0,
        "threats_detected": 0,
        "most_frequent_address": None,
    }

    display_security_insights(insights)

    captured = capsys.readouterr()

    assert "SECURITY INSIGHTS" in captured.out
    assert "Most Frequent Address  : N/A" in captured.out


from app.response.incident_manager import (
    create_incident,
    clear_incidents,
)


def test_display_incident_summary(capsys):
    """
    Test that the incident summary is displayed correctly.
    """

    clear_incidents()

    create_incident({
        "remote_address": "203.0.113.10:443",
        "severity": "HIGH",
    })

    create_incident({
        "remote_address": "198.51.100.20:80",
        "severity": "MEDIUM",
    })

    display_incident_summary()

    captured = capsys.readouterr()

    assert "INCIDENT SUMMARY" in captured.out
    assert "Total Incidents" in captured.out
    assert "2" in captured.out
    assert "HIGH" in captured.out
    assert "MEDIUM" in captured.out