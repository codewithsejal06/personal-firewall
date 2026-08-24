import ipaddress


def get_ip_from_address(address):
    """
    Extract the IP address from an address string.
    Example: '192.168.1.10:8080' -> '192.168.1.10'
    """
    if not address or address == "N/A":
        return None

    # IPv6 addresses in our monitor can appear with colons,
    # so they need special handling.
    if address.startswith("["):
        return address.split("]")[0][1:]

    # For IPv4, remove the port from the end.
    if address.count(":") == 1:
        return address.rsplit(":", 1)[0]

    return address


def is_local_ip(ip_address):
    """Return True if the address represents local/loopback traffic."""
    if not ip_address:
        return False

    try:
        ip = ipaddress.ip_address(ip_address)

        return (
            ip.is_loopback
            or ip.is_unspecified
            or ip.is_private
            or ip.is_link_local
        )
    except ValueError:
        return False


def classify_connection(connection):
    """
    Classify a network connection based on its status and endpoints.
    """
    status = connection.get("status", "N/A")
    remote_address = connection.get("remote_address", "N/A")

    # First check whether a service is listening.
    if status == "LISTEN":
        return "LISTENING"

    # UDP sockets may not have TCP-style statuses.
    if remote_address == "N/A":
        return "LOCAL / NO REMOTE ENDPOINT"

    remote_ip = get_ip_from_address(remote_address)

    if remote_ip and is_local_ip(remote_ip):
        return "LOCAL"

    if remote_ip:
        if status == "ESTABLISHED":
            return "EXTERNAL - ACTIVE"

        return "EXTERNAL"

    return "UNKNOWN"