from unittest import result

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

    assert len(result) == 1
    assert result[0]["firewall_decision"] == "BLOCK"
    assert result[0]["severity"] == "HIGH"
    assert len(dashboard_received_data) == 1
    assert dashboard_received_data[0]["severity"] == "HIGH"

def test_dashboard_receives_pipeline_processed_connections():

    connections = [
        {
            "remote_address": "203.0.113.10:443"
        }
    ]

    dashboard_received_data = []

    def dashboard_callback(data):
        dashboard_received_data.extend(data)

    run_monitoring_cycle(
        connections,
        callback=dashboard_callback
    )

    assert len(dashboard_received_data) == 1
    assert dashboard_received_data[0]["firewall_decision"] == "BLOCK"
    assert dashboard_received_data[0]["severity"] == "HIGH"