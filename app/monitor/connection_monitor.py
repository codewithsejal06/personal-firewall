from multiprocessing.dummy import connection

from app.detection.threat_detector import detect_threat
from app.utils.security_logger import log_firewall_event
from app.firewall.rules import evaluate_connection
from app.monitor.traffic_classifier import classify_connection
import socket
import psutil


def get_protocol(connection_type):
    """Convert the socket type into a readable protocol name."""
    if connection_type == socket.SOCK_STREAM:
        return "TCP"
    elif connection_type == socket.SOCK_DGRAM:
        return "UDP"

    return "UNKNOWN"


def get_active_connections():
    """Collect active internet network connections."""
    connections = psutil.net_connections(kind="inet")
    connection_data = []

    for connection in connections:
        local_address = "N/A"
        remote_address = "N/A"

        if connection.laddr:
            local_address = f"{connection.laddr.ip}:{connection.laddr.port}"

        if connection.raddr:
            remote_address = f"{connection.raddr.ip}:{connection.raddr.port}"

        connection_info = {
            "protocol": get_protocol(connection.type),
            "local_address": local_address,
            "remote_address": remote_address,
            "status": connection.status or "N/A",
        }

        connection_info["classification"] = classify_connection(connection_info)

        firewall_result = evaluate_connection(connection_info)

        connection_info["firewall_decision"] = firewall_result["decision"]
        connection_info["firewall_reason"] = firewall_result["reason"]

        threat_result = detect_threat(connection_info)

        connection_info["threat_detected"] = threat_result["threat_detected"]
        connection_info["severity"] = threat_result["severity"]
        connection_info["alerts"] = threat_result["alerts"]

        log_firewall_event(connection_info)

        connection_data.append(connection_info)

    return connection_data


def display_connections():
    """Display collected network connections."""
    connections = get_active_connections()

    print("\n" + "=" * 100)
    print("ACTIVE NETWORK CONNECTIONS")
    print("=" * 100)

    if not connections:
        print("No network connections found.")
        return

    for number, connection in enumerate(connections, start=1):
        print(f"\nConnection #{number}")
        print(f"  Protocol       : {connection['protocol']}")
        print(f"  Local Address  : {connection['local_address']}")
        print(f"  Remote Address : {connection['remote_address']}")
        print(f"  Status         : {connection['status']}")
        print(f"  Classification : {connection['classification']}")
        print(f"  Firewall Decision : {connection['firewall_decision']}")
        print(f"  Firewall Reason : {connection['firewall_reason']}")
        print(f"  Threat Detected   : {connection['threat_detected']}")
        print(f"  Severity          : {connection['severity']}")

        if connection["alerts"]:
            print("  Security Alerts:")
            for alert in connection["alerts"]:
                print(f"    - {alert}")
if __name__ == "__main__":
    display_connections()