from app.dashboard.dashboard_manager import run_security_dashboard
from app.monitor.monitoring_service import start_monitoring

def main():
    print("=" * 60)
    print("PERSONAL FIREWALL & NETWORK SECURITY MONITOR")
    print("System initialized successfully.")
    print("=" * 60)


def demo_security_report():
    """
    Demonstrate security monitoring with dashboard integration.
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

    start_monitoring(
        sample_connections,
        callback=run_security_dashboard,
        cycles=3,
        interval=3
    )


if __name__ == "__main__":
    main()
    demo_security_report()