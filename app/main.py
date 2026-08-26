from app.dashboard.statistics import calculate_security_statistics
from app.dashboard.report_generator import generate_security_report


def main():
    print("=" * 60)
    print("PERSONAL FIREWALL & NETWORK SECURITY MONITOR")
    print("System initialized successfully.")
    print("=" * 60)


def generate_firewall_summary(connections):
    """
    Generate a complete security summary from processed connections.
    """

    statistics = calculate_security_statistics(connections)
    report = generate_security_report(statistics)

    return report


def demo_security_report():
    """
    Demonstrate security report generation.
    """

    sample_connections = [
        {
            "firewall_decision": "ALLOW",
            "threat_detected": False,
            "severity": "LOW"
        },
        {
            "firewall_decision": "BLOCK",
            "threat_detected": True,
            "severity": "HIGH"
        }
    ]

    report = generate_firewall_summary(sample_connections)

    print("\n" + report)


if __name__ == "__main__":
    main()
    demo_security_report()