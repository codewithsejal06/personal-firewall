from app.firewall.rules import evaluate_connection


def test_normal_connection():
    """A normal connection should be allowed."""

    connection = {
        "protocol": "TCP",
        "local_address": "192.168.1.10:50000",
        "remote_address": "8.8.8.8:443",
        "status": "ESTABLISHED",
    }

    result = evaluate_connection(connection)

    assert result["decision"] == "ALLOW"


def test_blocked_ip():
    """A connection to a blocked IP should be blocked."""

    connection = {
        "protocol": "TCP",
        "local_address": "192.168.1.10:50000",
        "remote_address": "203.0.113.10:443",
        "status": "ESTABLISHED",
    }

    result = evaluate_connection(connection)

    assert result["decision"] == "BLOCK"


def test_blocked_port():
    """A connection using a blocked remote port should be blocked."""

    connection = {
        "protocol": "TCP",
        "local_address": "192.168.1.10:50000",
        "remote_address": "8.8.8.8:23",
        "status": "ESTABLISHED",
    }

    result = evaluate_connection(connection)

    assert result["decision"] == "BLOCK"