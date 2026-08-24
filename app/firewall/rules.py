# Demo firewall rules.
# These rules are only used by our application and do not modify
# the operating system firewall.

BLOCKED_IPS = {
    "203.0.113.10",
    "198.51.100.25",
}

BLOCKED_PORTS = {
    23,  # Telnet - legacy plaintext remote access
}


def get_ip_from_address(address):
    """Extract an IP address from an address string."""
    if not address or address == "N/A":
        return None

    # Handle IPv6 addresses such as [::1]:8080.
    if address.startswith("["):
        return address.split("]")[0][1:]

    # Handle IPv4 address:port.
    if address.count(":") == 1:
        return address.rsplit(":", 1)[0]

    return address


def get_port_from_address(address):
    """Extract a port number from an address string."""
    if not address or address == "N/A":
        return None

    if address.startswith("[") and "]:" in address:
        return int(address.rsplit(":", 1)[1])

    if address.count(":") == 1:
        try:
            return int(address.rsplit(":", 1)[1])
        except ValueError:
            return None

    return None


def evaluate_connection(connection):
    """
    Evaluate a network connection against firewall rules.

    Returns:
        A dictionary containing the firewall decision and reason.
    """
    remote_address = connection.get("remote_address", "N/A")
    remote_ip = get_ip_from_address(remote_address)
    remote_port = get_port_from_address(remote_address)

    # Rule 1: Block explicitly blocked IP addresses.
    if remote_ip in BLOCKED_IPS:
        return {
            "decision": "BLOCK",
            "reason": f"Remote IP {remote_ip} matches the blocked IP rule.",
        }

    # Rule 2: Block explicitly blocked remote ports.
    if remote_port in BLOCKED_PORTS:
        return {
            "decision": "BLOCK",
            "reason": f"Remote port {remote_port} matches the blocked port rule.",
        }

    # Default policy.
    return {
        "decision": "ALLOW",
        "reason": "No blocking rule matched. Default policy allows the connection.",
    }