# Basic threat detection rules for the Personal Firewall project.
# These rules analyze existing connection information and do not
# create, modify, or interrupt network traffic.

SUSPICIOUS_IPS = {
    "198.51.100.50",
    "203.0.113.200",
}

# Demonstration ports that may require additional attention.
# A port alone does not prove malicious activity.
SUSPICIOUS_PORTS = {
    23,
    445,
}


def get_ip_from_address(address):
    """Extract an IP address from an address string."""
    if not address or address == "N/A":
        return None

    if address.startswith("["):
        return address.split("]")[0][1:]

    if address.count(":") == 1:
        return address.rsplit(":", 1)[0]

    return address


def get_port_from_address(address):
    """Extract a port number from an address string."""
    if not address or address == "N/A":
        return None

    if address.startswith("[") and "]:" in address:
        try:
            return int(address.rsplit(":", 1)[1])
        except ValueError:
            return None

    if address.count(":") == 1:
        try:
            return int(address.rsplit(":", 1)[1])
        except ValueError:
            return None

    return None


def detect_threat(connection):
    """
    Analyze a connection and return threat detection information.
    """

    alerts = []

    remote_address = connection.get("remote_address", "N/A")
    remote_ip = get_ip_from_address(remote_address)
    remote_port = get_port_from_address(remote_address)

    # Indicator 1: Firewall already blocked this connection.
    if connection.get("firewall_decision") == "BLOCK":
        alerts.append(
            "Firewall blocked this connection. Security review is recommended."
        )

    # Indicator 2: Configured suspicious IP.
    if remote_ip in SUSPICIOUS_IPS:
        alerts.append(
            f"Remote IP {remote_ip} matches the suspicious IP list."
        )

    # Indicator 3: Configured suspicious remote port.
    if remote_port in SUSPICIOUS_PORTS:
        alerts.append(
            f"Remote port {remote_port} is configured for additional monitoring."
        )

    # Determine severity.
    if connection.get("firewall_decision") == "BLOCK":
        severity = "HIGH"
    elif len(alerts) >= 2:
        severity = "HIGH"
    elif len(alerts) == 1:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    return {
        "threat_detected": len(alerts) > 0,
        "severity": severity,
        "alerts": alerts,
    }