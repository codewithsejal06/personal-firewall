import json

from app.detection.threat_blocking import automatically_block_threat
from app.firewall.blocklist_manager import BlocklistManager


def create_test_manager(tmp_path):

    policy = {
        "blocked_ips": [],
        "blocked_ports": [23, 445],
        "suspicious_ips": [],
        "monitoring": {
            "max_events": 100,
            "alert_threshold": "MEDIUM"
        }
    }

    config_file = tmp_path / "security_policy.json"

    with open(config_file, "w", encoding="utf-8") as file:
        json.dump(policy, file)

    return BlocklistManager(config_file)


def test_high_severity_threat_is_automatically_blocked(tmp_path):

    manager = create_test_manager(tmp_path)

    connection = {
        "remote_address": "192.168.1.250:443",
        "threat_detected": True,
        "severity": "HIGH"
    }

    result = automatically_block_threat(connection, manager)

    assert result["blocked"] is True
    assert result["ip_address"] == "192.168.1.250"
    assert manager.is_ip_blocked("192.168.1.250") is True


def test_low_severity_threat_is_not_automatically_blocked(tmp_path):

    manager = create_test_manager(tmp_path)

    connection = {
        "remote_address": "192.168.1.251:80",
        "threat_detected": True,
        "severity": "LOW"
    }

    result = automatically_block_threat(connection, manager)

    assert result["blocked"] is False
    assert manager.is_ip_blocked("192.168.1.251") is False


def test_normal_connection_is_not_blocked(tmp_path):

    manager = create_test_manager(tmp_path)

    connection = {
        "remote_address": "192.168.1.252:443",
        "threat_detected": False,
        "severity": "LOW"
    }

    result = automatically_block_threat(connection, manager)

    assert result["blocked"] is False
    assert manager.is_ip_blocked("192.168.1.252") is False