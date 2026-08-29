from types import SimpleNamespace
import socket

from app.monitor.connection_collector import (
    collect_active_connections,
    format_address,
    get_protocol,
)


def test_format_ipv4_address():

    result = format_address(("192.168.1.10", 443))

    assert result == "192.168.1.10:443"


def test_get_protocol_for_tcp():

    result = get_protocol(socket.SOCK_STREAM)

    assert result == "TCP"


def test_get_protocol_for_udp():

    result = get_protocol(socket.SOCK_DGRAM)

    assert result == "UDP"


def test_collect_active_connections(monkeypatch):

    sample_connections = [
        SimpleNamespace(
            laddr=("192.168.1.5", 50000),
            raddr=("198.51.100.50", 443),
            status="ESTABLISHED",
            type=socket.SOCK_STREAM,
            pid=1234,
        )
    ]

    def mock_net_connections(kind):

        return sample_connections

    monkeypatch.setattr(
        "app.monitor.connection_collector.psutil.net_connections",
        mock_net_connections,
    )

    result = collect_active_connections()

    assert len(result) == 1
    assert result[0]["remote_address"] == "198.51.100.50:443"
    assert result[0]["protocol"] == "TCP"
    assert result[0]["status"] == "ESTABLISHED"