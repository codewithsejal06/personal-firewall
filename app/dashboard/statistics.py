def calculate_security_statistics(connections):
    """
    Calculate security statistics from monitored connections.
    """

    statistics = {
        "total_connections": len(connections),
        "allowed_connections": 0,
        "blocked_connections": 0,
        "threats_detected": 0,
        "high_severity": 0,
        "medium_severity": 0,
        "low_severity": 0,
    }

    for connection in connections:

        if connection.get("firewall_decision") == "ALLOW":
            statistics["allowed_connections"] += 1

        elif connection.get("firewall_decision") == "BLOCK":
            statistics["blocked_connections"] += 1

        if connection.get("threat_detected"):
            statistics["threats_detected"] += 1

        severity = connection.get("severity", "").upper()

        if severity == "HIGH":
            statistics["high_severity"] += 1

        elif severity == "MEDIUM":
            statistics["medium_severity"] += 1

        elif severity == "LOW":
            statistics["low_severity"] += 1

    return statistics