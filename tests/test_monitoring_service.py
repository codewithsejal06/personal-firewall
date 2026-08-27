from app.monitor.monitoring_service import run_monitoring_cycle


def test_monitoring_cycle_returns_connections():

    connections = [
        {
            "firewall_decision": "ALLOW",
            "threat_detected": False,
            "severity": "LOW"
        }
    ]

    result = run_monitoring_cycle(connections)

    assert result == connections


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




from app.monitor.monitoring_service import start_monitoring


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