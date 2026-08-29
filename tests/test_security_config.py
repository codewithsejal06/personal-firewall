from app.config.security_config import load_security_policy


def test_load_security_policy():

    policy = load_security_policy()

    assert "blocked_ips" in policy
    assert "blocked_ports" in policy
    assert "suspicious_ips" in policy
    assert "monitoring" in policy