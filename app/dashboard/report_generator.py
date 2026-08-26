def generate_security_report(statistics):
    """
    Generate a readable security report from collected statistics.
    """

    report = f"""
PERSONAL FIREWALL SECURITY REPORT
================================

Connection Summary
------------------
Total Connections : {statistics["total_connections"]}
Allowed Connections : {statistics["allowed_connections"]}
Blocked Connections : {statistics["blocked_connections"]}
Threats Detected : {statistics["threats_detected"]}

Severity Summary
----------------
HIGH Severity   : {statistics["high_severity"]}
MEDIUM Severity : {statistics["medium_severity"]}
LOW Severity    : {statistics["low_severity"]}
"""

    return report.strip()