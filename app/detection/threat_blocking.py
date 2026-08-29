import ipaddress

from app.firewall.blocklist_manager import BlocklistManager


def extract_ip_address(remote_address):
    """
    Extract and validate an IP address from a remote address.
    """

    if not remote_address:
        return None

    remote_address = str(remote_address)

    # Supports values such as:
    # "192.168.1.200"
    # "192.168.1.200:443"
    ip_value = remote_address.split(":")[0]

    try:
        return str(ipaddress.ip_address(ip_value))
    except ValueError:
        return None


def automatically_block_threat(connection, blocklist_manager=None):
    """
    Automatically add an IP address to the blocklist when a
    HIGH-severity security threat is detected.
    """

    if blocklist_manager is None:
        blocklist_manager = BlocklistManager()

    threat_detected = connection.get("threat_detected", False)
    severity = connection.get("severity", "").upper()

    remote_address = connection.get("remote_address")

    if not threat_detected:
        return {
            "blocked": False,
            "reason": "No security threat detected."
        }

    if severity != "HIGH":
        return {
            "blocked": False,
            "reason": "Threat severity is not high enough for automatic blocking."
        }

    ip_address = extract_ip_address(remote_address)

    if not ip_address:
        return {
            "blocked": False,
            "reason": "Valid remote IP address not available."
        }

    added = blocklist_manager.add_blocked_ip(ip_address)

    if added:
        return {
            "blocked": True,
            "ip_address": ip_address,
            "reason": "High-severity threat IP automatically added to blocklist."
        }

    return {
        "blocked": False,
        "ip_address": ip_address,
        "reason": "IP address is already in the blocklist."
    }