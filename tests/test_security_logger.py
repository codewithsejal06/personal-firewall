from app.utils.security_logger import log_firewall_event, LOG_FILE


def test_security_event_logging():
    """Verify that a firewall event is written to the log file."""

    test_connection = {
        "protocol": "TCP",
        "local_address": "192.168.1.10:50000",
        "remote_address": "203.0.113.10:443",
        "classification": "EXTERNAL - ACTIVE",
        "firewall_decision": "BLOCK",
        "firewall_reason": "Test blocked IP rule.",
    }

    log_firewall_event(test_connection)

    # Ensure Python writes any buffered log data to the file.
    for handler in __import__("logging").getLogger("personal_firewall").handlers:
        handler.flush()

    assert LOG_FILE.exists()

    log_content = LOG_FILE.read_text(encoding="utf-8")

    assert "Protocol=TCP" in log_content
    assert "Decision=BLOCK" in log_content
    assert "Test blocked IP rule." in log_content