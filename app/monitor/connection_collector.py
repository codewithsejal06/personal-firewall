import socket

import psutil


def format_address(address):
    """
    Convert a network address into a readable string.
    """

    if not address:
        return "N/A"

    host = address[0]
    port = address[1]

    # Format IPv6 addresses clearly.
    if ":" in host:
        return f"[{host}]:{port}"

    return f"{host}:{port}"


def get_protocol(connection_type):
    """
    Convert the socket type into a readable protocol name.
    """

    if connection_type == socket.SOCK_STREAM:
        return "TCP"

    if connection_type == socket.SOCK_DGRAM:
        return "UDP"

    return "UNKNOWN"


def collect_active_connections():
    """
    Collect active network connections from the local system.

    Only connection metadata is collected. No packet contents or
    private communication data is captured.
    """

    collected_connections = []

    connections = psutil.net_connections(kind="inet")

    for connection in connections:

        # Ignore connections that do not have a remote address.
        if not connection.raddr:
            continue

        connection_data = {
            "local_address": format_address(connection.laddr),
            "remote_address": format_address(connection.raddr),
            "status": connection.status,
            "protocol": get_protocol(connection.type),
            "pid": connection.pid,
        }

        collected_connections.append(connection_data)

    return collected_connections