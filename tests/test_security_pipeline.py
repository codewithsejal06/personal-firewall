import json

from app.core.security_pipeline import process_security_connection
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


def test_normal_connection_flows_through_pipeline(tmp_path):

    manager = create_test_manager(tmp_path)

    connection = {
        "remote_address": "192.168.1.50:443"
    }

    result = process_security_connection(
        connection,
        blocklist_manager=manager,
        save_event=False
    )

    assert result["firewall_decision"] == "ALLOW"
    assert result["threat_detected"] is False
    assert result["severity"] == "LOW"


def test_firewall_blocked_connection_is_high_severity(tmp_path):

    manager = create_test_manager(tmp_path)

    connection = {
        "remote_address": "203.0.113.10:443"
    }

    result = process_security_connection(
        connection,
        blocklist_manager=manager,
        save_event=False
    )

    assert result["firewall_decision"] == "BLOCK"
    assert result["threat_detected"] is True
    assert result["severity"] == "HIGH"


def test_persistent_blocklist_is_enforced(tmp_path):

    manager = create_test_manager(tmp_path)

    manager.add_blocked_ip("192.168.1.250")

    connection = {
        "remote_address": "192.168.1.250:443"
    }

    result = process_security_connection(
        connection,
        blocklist_manager=manager,
        save_event=False
    )

    assert result["firewall_decision"] == "BLOCK"
    assert result["threat_detected"] is True
    assert result["severity"] == "HIGH"