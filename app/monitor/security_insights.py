from collections import Counter


def generate_security_insights(connections):
    """
    Generate security insights from processed network connections.

    Returns a dictionary containing connection and security statistics.
    """

    remote_addresses = [
        connection.get("remote_address", "N/A")
        for connection in connections
        if connection.get("remote_address")
        and connection.get("remote_address") != "N/A"
    ]

    address_counts = Counter(remote_addresses)

    total_connections = len(connections)

    unique_connections = len(address_counts)

    repeated_connections = sum(
        count - 1
        for count in address_counts.values()
        if count > 1
    )

    blocked_connections = sum(
        1
        for connection in connections
        if connection.get("firewall_decision") == "BLOCK"
    )

    threats_detected = sum(
        1
        for connection in connections
        if connection.get("threat_detected") is True
    )

    most_frequent_address = None

    if address_counts:
        most_frequent_address = address_counts.most_common(1)[0][0]

    return {
        "total_connections": total_connections,
        "unique_connections": unique_connections,
        "repeated_connections": repeated_connections,
        "blocked_connections": blocked_connections,
        "threats_detected": threats_detected,
        "most_frequent_address": most_frequent_address,
    }