from datetime import datetime


# Stores connections seen during the current application session.
TRACKED_CONNECTIONS = {}


def get_connection_key(connection):
    """
    Create a unique key used to identify a network connection.
    """

    protocol = connection.get("protocol", "UNKNOWN")
    local_address = connection.get("local_address", "N/A")
    remote_address = connection.get("remote_address", "N/A")

    return (
        protocol,
        local_address,
        remote_address,
    )


def track_connection(connection):
    """
    Track a processed network connection.

    Returns information about whether the connection is new
    or has been seen previously during the current session.
    """

    connection_key = get_connection_key(connection)
    current_time = datetime.now().isoformat(timespec="seconds")

    if connection_key not in TRACKED_CONNECTIONS:

        TRACKED_CONNECTIONS[connection_key] = {
            "first_seen": current_time,
            "last_seen": current_time,
            "seen_count": 1,
        }

        return {
            "is_new": True,
            "first_seen": current_time,
            "last_seen": current_time,
            "seen_count": 1,
        }

    tracked_data = TRACKED_CONNECTIONS[connection_key]

    tracked_data["last_seen"] = current_time
    tracked_data["seen_count"] += 1

    return {
        "is_new": False,
        "first_seen": tracked_data["first_seen"],
        "last_seen": tracked_data["last_seen"],
        "seen_count": tracked_data["seen_count"],
    }


def clear_tracked_connections():
    """
    Clear all tracked connections.

    This is useful for testing and starting a new monitoring session.
    """

    TRACKED_CONNECTIONS.clear()