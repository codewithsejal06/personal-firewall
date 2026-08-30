from app.monitor.monitoring_service import run_live_monitoring_cycle

from app.monitor.monitoring_service import run_monitoring_cycle

def test_end_to_end_monitoring_cycle_with_dashboard_callback():

    received_connections = []

    raw_connections = [
        {
            "protocol": "TCP",
            "local_address": "192.168.1.5:5000",
            "remote_address": "203.0.113.10:443",
        },
        {
            "protocol": "TCP",
            "local_address": "192.168.1.5:5001",
            "remote_address": "192.168.1.10:443",
        },
    ]

    def dashboard_callback(connections):
        received_connections.extend(connections)

    result = run_monitoring_cycle(
        raw_connections,
        callback=dashboard_callback
    )

    # Verify both connections were processed
    assert len(result) == 2

    # Verify firewall processing
    assert result[0]["firewall_decision"] == "BLOCK"
    assert result[1]["firewall_decision"] == "ALLOW"

    # Verify threat detection
    assert result[0]["threat_detected"] is True
    assert result[1]["threat_detected"] is False

    # Verify the dashboard received processed data
    assert len(received_connections) == 2
    assert received_connections[0]["severity"] == "HIGH"
    assert received_connections[1]["severity"] == "LOW"

from app.core.security_pipeline import process_security_connection
from app.monitor.connection_tracker import (
    track_connection,
    clear_tracked_connections,
    TRACKED_CONNECTIONS,
)
from app.monitor.security_insights import generate_security_insights


def test_end_to_end_security_workflow():

    # Start with a clean connection tracking session
    clear_tracked_connections()

    connections = [
        {
            "protocol": "TCP",
            "local_address": "192.168.1.5:5000",
            "remote_address": "203.0.113.10:443",
        },
        {
            "protocol": "TCP",
            "local_address": "192.168.1.5:5001",
            "remote_address": "198.51.100.50:443",
        },
        {
            "protocol": "TCP",
            "local_address": "192.168.1.5:5002",
            "remote_address": "192.168.1.10:443",
        },
    ]

    processed_connections = []

    # Process every connection through the security pipeline
    for connection in connections:
        processed_connection = process_security_connection(connection)
        processed_connections.append(processed_connection)

    # Verify that every connection was processed
    assert len(processed_connections) == 3

    # Verify firewall behavior
    assert processed_connections[0]["firewall_decision"] == "BLOCK"
    assert processed_connections[1]["firewall_decision"] == "ALLOW"
    assert processed_connections[2]["firewall_decision"] == "ALLOW"

    # Verify threat detection
    assert processed_connections[0]["threat_detected"] is True
    assert processed_connections[1]["threat_detected"] is True
    assert processed_connections[2]["threat_detected"] is False

    # Verify connection tracking
    for connection in processed_connections:
        track_connection(connection)

    assert len(TRACKED_CONNECTIONS) == 3

    # Verify security insights
    insights = generate_security_insights(processed_connections)

    assert insights["total_connections"] == 3
    assert insights["blocked_connections"] == 1
    assert insights["threats_detected"] == 2

    # Clean up after the test
    clear_tracked_connections()


from app.monitor.connection_tracker import (
    get_connection_key,
    track_connection,
    clear_tracked_connections,
    TRACKED_CONNECTIONS,
)


def test_connection_tracking_across_monitoring_cycles():

    clear_tracked_connections()

    connection = {
        "protocol": "TCP",
        "local_address": "192.168.1.5:5000",
        "remote_address": "192.168.1.10:443",
    }

    # First monitoring cycle
    first_result = track_connection(connection)

    assert first_result["is_new"] is True
    assert first_result["seen_count"] == 1

    # Second monitoring cycle - same connection appears again
    second_result = track_connection(connection)

    assert second_result["is_new"] is False
    assert second_result["seen_count"] == 2

    # Verify only one unique connection is stored
    assert len(TRACKED_CONNECTIONS) == 1

    # Verify the stored connection key exists
    connection_key = get_connection_key(connection)
    assert connection_key in TRACKED_CONNECTIONS

    clear_tracked_connections()


def test_end_to_end_live_monitoring_cycle():

    received_connections = []

    def dashboard_callback(connections):
        received_connections.extend(connections)

    result = run_live_monitoring_cycle(
        callback=dashboard_callback
    )

    # Verify that the live monitoring cycle returns a list
    assert isinstance(result, list)

    # Verify that the dashboard callback receives the same connections
    assert received_connections == result

    # Verify that collected connections contain security processing data
    for connection in result:
        assert "firewall_decision" in connection
        assert "threat_detected" in connection
        assert "severity" in connection