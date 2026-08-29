import json

from app.firewall.blocklist_manager import BlocklistManager


def create_test_policy(tmp_path):
    """
    Create a temporary security policy for testing.
    """

    policy = {
        "blocked_ips": [],
        "blocked_ports": [23, 445],
        "suspicious_ips": ["10.0.0.99"],
        "monitoring": {
            "max_events": 100,
            "alert_threshold": "MEDIUM"
        }
    }

    config_file = tmp_path / "security_policy.json"

    with open(config_file, "w", encoding="utf-8") as file:
        json.dump(policy, file)

    return config_file


def test_add_blocked_ip(tmp_path):

    config_file = create_test_policy(tmp_path)

    manager = BlocklistManager(config_file)

    result = manager.add_blocked_ip("192.168.1.50")

    assert result is True
    assert manager.is_ip_blocked("192.168.1.50") is True


def test_remove_blocked_ip(tmp_path):

    config_file = create_test_policy(tmp_path)

    manager = BlocklistManager(config_file)

    manager.add_blocked_ip("192.168.1.50")

    result = manager.remove_blocked_ip("192.168.1.50")

    assert result is True
    assert manager.is_ip_blocked("192.168.1.50") is False


def test_duplicate_blocked_ip(tmp_path):

    config_file = create_test_policy(tmp_path)

    manager = BlocklistManager(config_file)

    manager.add_blocked_ip("192.168.1.50")

    result = manager.add_blocked_ip("192.168.1.50")

    assert result is False