from app.monitor.monitoring_service import run_monitoring_cycle


def test_monitoring_cycle_updates_dashboard():

    connections = [
        {
            "firewall_decision": "BLOCK",
            "threat_detected": True,
            "severity": "HIGH"
        }
    ]

    dashboard_received_data = []

    def dashboard_callback(data):
        dashboard_received_data.extend(data)

    result = run_monitoring_cycle(
        connections,
        callback=dashboard_callback
    )

    assert result == connections
    assert len(dashboard_received_data) == 1
    assert dashboard_received_data[0]["severity"] == "HIGH"