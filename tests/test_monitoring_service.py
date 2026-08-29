from app.monitor.monitoring_service import (
    run_monitoring_cycle,
    run_live_monitoring_cycle,
    start_monitoring,
)


def test_monitoring_cycle_returns_connections():

    connections = [
        {
            "firewall_decision": "ALLOW",
            "threat_detected": False,
            "severity": "LOW"
        }
    ]

    result = run_monitoring_cycle(connections)

    assert len(result) == 1
    assert result[0]["firewall_decision"] == "ALLOW"
    assert result[0]["severity"] == "LOW"
    assert "firewall_reason" in result[0]


def test_monitoring_cycle_calls_callback():

    connections = [
        {
            "firewall_decision": "BLOCK",
            "threat_detected": True,
            "severity": "HIGH"
        }
    ]

    callback_called = False

    def test_callback(data):
        nonlocal callback_called
        callback_called = True

    run_monitoring_cycle(connections, test_callback)

    assert callback_called is True


def test_start_monitoring_runs_multiple_cycles():

    connections = [
        {
            "firewall_decision": "ALLOW",
            "threat_detected": False,
            "severity": "LOW"
        }
    ]

    callback_count = 0

    def test_callback(data):
        nonlocal callback_count
        callback_count += 1

    start_monitoring(
        connections,
        callback=test_callback,
        cycles=3,
        interval=0
    )

    assert callback_count == 3


def test_start_monitoring_finishes_after_specified_cycles():

    connections = [
        {
            "firewall_decision": "ALLOW",
            "threat_detected": False,
            "severity": "LOW"
        }
    ]

    callback_count = 0

    def test_callback(data):
        nonlocal callback_count
        callback_count += 1

    start_monitoring(
        connections,
        callback=test_callback,
        cycles=2,
        interval=0
    )

    assert callback_count == 2


def test_monitoring_cycle_processes_connection_through_pipeline():

    connections = [
        {
            "remote_address": "203.0.113.10:443"
        }
    ]

    result = run_monitoring_cycle(connections)

    assert len(result) == 1
    assert result[0]["firewall_decision"] == "BLOCK"
    assert result[0]["threat_detected"] is True
    assert result[0]["severity"] == "HIGH"


# -----------------------------------------
# Sprint 12.2: Live Connection Monitoring
# -----------------------------------------

def test_live_monitoring_cycle_collects_and_processes_connections(
    monkeypatch
):

    sample_connections = [
        {
            "remote_address": "198.51.100.50:443"
        }
    ]

    def mock_collect_connections():
        return sample_connections

    monkeypatch.setattr(
        "app.monitor.monitoring_service.collect_active_connections",
        mock_collect_connections
    )

    result = run_live_monitoring_cycle()

    assert len(result) == 1
    assert result[0]["remote_address"] == "198.51.100.50:443"
    assert "firewall_decision" in result[0]
    assert "severity" in result[0]