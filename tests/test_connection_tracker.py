from app.monitor.connection_tracker import (
    clear_tracked_connections,
    get_connection_key,
    track_connection,
)


def test_get_connection_key():

    connection = {
        "protocol": "TCP",
        "local_address": "192.168.1.10:50000",
        "remote_address": "198.51.100.50:443",
    }

    result = get_connection_key(connection)

    assert result == (
        "TCP",
        "192.168.1.10:50000",
        "198.51.100.50:443",
    )


def test_new_connection_is_tracked():

    clear_tracked_connections()

    connection = {
        "protocol": "TCP",
        "local_address": "192.168.1.10:50000",
        "remote_address": "198.51.100.50:443",
    }

    result = track_connection(connection)

    assert result["is_new"] is True
    assert result["seen_count"] == 1


def test_existing_connection_updates_tracking():

    clear_tracked_connections()

    connection = {
        "protocol": "TCP",
        "local_address": "192.168.1.10:50000",
        "remote_address": "198.51.100.50:443",
    }

    first_result = track_connection(connection)
    second_result = track_connection(connection)

    assert first_result["is_new"] is True
    assert second_result["is_new"] is False
    assert second_result["seen_count"] == 2
    assert second_result["first_seen"] == first_result["first_seen"]