from app.firewall.blocklist_manager import BlocklistManager


def enforce_blocklist(connection, blocklist_manager=None):
    """
    Check whether a connection's remote IP address is present
    in the persistent blocklist.

    Returns the updated connection dictionary.
    """

    if blocklist_manager is None:
        blocklist_manager = BlocklistManager()

    remote_address = connection.get("remote_address", "")

    if not remote_address:
        return connection

    remote_ip = str(remote_address).split(":")[0]

    if blocklist_manager.is_ip_blocked(remote_ip):
        updated_connection = connection.copy()

        updated_connection["firewall_decision"] = "BLOCK"
        updated_connection["blocked_reason"] = (
            "Remote IP address is present in the persistent blocklist."
        )

        return updated_connection

    return connection