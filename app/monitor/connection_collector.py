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


def get_direction(local_address, remote_address):
    """
    Determine the likely traffic direction from connection ports.

    This is an application-level classification based on connection
    metadata. It does not inspect packet contents.
    """

    if not local_address or not remote_address:
        return "UNKNOWN"

    local_port = local_address[1]
    remote_port = remote_address[1]

    # Common server/service ports.
    well_known_ports = {
        20,
        21,
        22,
        23,
        25,
        53,
        80,
        110,
        143,
        443,
        445,
        587,
        993,
        995,
    }

    # Local well-known port + remote ephemeral port
    # usually represents an inbound connection.
    if (
        local_port in well_known_ports
        and remote_port >= 1024
    ):
        return "INBOUND"

    # Local ephemeral port + remote well-known port
    # usually represents an outbound connection.
    if (
        local_port >= 1024
        and remote_port in well_known_ports
    ):
        return "OUTBOUND"

    # Most client-side connections use an ephemeral
    # local port.
    if local_port >= 1024:
        return "OUTBOUND"

    return "UNKNOWN"


def collect_active_connections():
    """
    Collect active network connections from the local system.

    Only connection metadata is collected. No packet contents or
    private communication data is captured.
    """

    collected_connections = []

    connections = psutil.net_connections(
        kind="inet"
    )

    for connection in connections:

        # Ignore connections that do not have
        # a remote address.
        if not connection.raddr:
            continue

        connection_data = {
            "local_address": format_address(
                connection.laddr
            ),

            "remote_address": format_address(
                connection.raddr
            ),

            "status": connection.status,

            "protocol": get_protocol(
                connection.type
            ),

            "direction": get_direction(
                connection.laddr,
                connection.raddr
            ),

            "pid": connection.pid,
        }

        collected_connections.append(
            connection_data
        )

    return collected_connections