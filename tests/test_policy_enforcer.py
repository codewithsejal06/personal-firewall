import json

from app.firewall.blocklist_manager import BlocklistManager
from app.firewall.policy_enforcer import enforce_blocklist


def create_test_manager(tmp_path):

    policy = {
        "blocked_ips": ["192.168.1.200"],
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


def test_persistently_blocked_ip_is_blocked(tmp_path):

    manager = create_test_manager(tmp_path)

    connection = {
        "remote_address": "192.168.1.200:443",
        "firewall_decision": "ALLOW"
    }

    result = enforce_blocklist(connection, manager)

    assert result["firewall_decision"] == "BLOCK"
    assert "persistent blocklist" in result["blocked_reason"]


def test_non_blocked_ip_remains_unchanged(tmp_path):

    manager = create_test_manager(tmp_path)

    connection = {
        "remote_address": "192.168.1.50:443",
        "firewall_decision": "ALLOW"
    }

    result = enforce_blocklist(connection, manager)

    assert result["firewall_decision"] == "ALLOW"