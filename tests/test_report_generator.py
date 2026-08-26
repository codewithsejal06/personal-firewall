from app.dashboard.report_generator import generate_security_report


def test_generate_security_report():

    statistics = {
        "total_connections": 10,
        "allowed_connections": 7,
        "blocked_connections": 3,
        "threats_detected": 2,
        "high_severity": 1,
        "medium_severity": 1,
        "low_severity": 0,
    }

    report = generate_security_report(statistics)

    assert "PERSONAL FIREWALL SECURITY REPORT" in report
    assert "Total Connections : 10" in report
    assert "Allowed Connections : 7" in report
    assert "Blocked Connections : 3" in report
    assert "Threats Detected : 2" in report
    assert "HIGH Severity   : 1" in report
    assert "MEDIUM Severity : 1" in report
    assert "LOW Severity    : 0" in report